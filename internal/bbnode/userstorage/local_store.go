package userstorage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
	"github.com/starius/barterbackup/storedpb"
)

const contentFileName = "content.bin"

// Filesystem abstracts persistent storage operations for user data.
type Filesystem interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte) error
}

var (
	ErrFileNotFound = errors.New("file not found")
	ErrStopped      = errors.New("storage stopped")
)

// contentSnapshot captures responder content metadata for quick access.
type contentSnapshot struct {
	id     []byte
	length int64
}

// Store maintains the encrypted user content metadata and files on disk.
type Store struct {
	fs           Filesystem
	files        map[string][]byte
	metadata     *storedpb.Metadata
	content      []byte
	contentID    []byte
	contentAEAD  cipher.AEAD
	metadataAEAD cipher.AEAD
	xor          usercontent.XORKeyStreamAt
	ivKey        []byte
}

// NewStore loads persisted state from the provided filesystem.
func NewStore(fsys Filesystem, master []byte) (*Store, error) {
	if fsys == nil {
		return nil, errors.New("filesystem is nil")
	}
	contentKey, err := keys.DeriveKey(master, "usercontent/content-id", 32)
	if err != nil {
		return nil, err
	}
	metaKey, err := keys.DeriveKey(master, "usercontent/metadata", 32)
	if err != nil {
		return nil, err
	}
	fileKey, err := keys.DeriveKey(master, "usercontent/files", 32)
	if err != nil {
		return nil, err
	}
	ivKey, err := keys.DeriveKey(master, "usercontent/iv", 32)
	if err != nil {
		return nil, err
	}

	contentAEAD, err := cipher.NewGCM(newAESBlock(contentKey))
	if err != nil {
		return nil, err
	}
	metadataAEAD, err := cipher.NewGCM(newAESBlock(metaKey))
	if err != nil {
		return nil, err
	}
	xor := makeXORKeyStream(newAESBlock(fileKey))

	store := &Store{
		fs:           fsys,
		files:        make(map[string][]byte),
		contentAEAD:  contentAEAD,
		metadataAEAD: metadataAEAD,
		xor:          xor,
		ivKey:        ivKey,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) load() error {
	data, err := s.fs.ReadFile(contentFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	uc, meta, cid, err := usercontent.ParseContentFile(bytes.NewReader(data), s.contentAEAD, s.metadataAEAD, s.xor, s.ivKey)
	if err != nil {
		return err
	}

	s.files = make(map[string][]byte, len(uc.Files))
	for name, file := range uc.Files {
		buf := make([]byte, file.Size)
		if file.Size > 0 {
			if _, err := file.Body.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		}
		s.files[name] = buf
	}

	s.metadata = meta
	s.content = bytes.Clone(data)
	s.contentID = append([]byte(nil), cid...)
	return nil
}

func (s *Store) setFile(name string, data []byte) error {
	if name == "" {
		return errors.New("file name is empty")
	}
	s.files[name] = append([]byte(nil), data...)
	return s.persist()
}

// SetFile persists or updates a file.
func (s *Store) SetFile(_ context.Context, name string, data []byte) error {
	return s.setFile(name, data)
}

func (s *Store) getFile(name string) ([]byte, error) {
	data, ok := s.files[name]
	if !ok {
		return nil, ErrFileNotFound
	}
	return append([]byte(nil), data...), nil
}

// GetFile retrieves a persisted file by name.
func (s *Store) GetFile(_ context.Context, name string) ([]byte, error) {
	return s.getFile(name)
}

func (s *Store) deleteFile(name string) error {
	if _, ok := s.files[name]; !ok {
		return ErrFileNotFound
	}
	delete(s.files, name)
	return s.persist()
}

// DeleteFile removes a file from persistent state.
func (s *Store) DeleteFile(_ context.Context, name string) error {
	return s.deleteFile(name)
}

func (s *Store) listFiles() []string {
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListFiles returns the sorted list of file names.
func (s *Store) ListFiles(_ context.Context) ([]string, error) {
	return s.listFiles(), nil
}

func (s *Store) persist() error {
	now := time.Now()
	uc := usercontent.UserContent{
		CreatedAt: now,
		Files:     cloneFiles(s.files),
	}
	if s.metadata != nil {
		uc.Peers = s.metadata.GetPeers()
	}

	var buf bytes.Buffer
	meta, cid, err := usercontent.WriteContentFile(&buf, uc, s.contentAEAD, s.metadataAEAD, s.xor, s.ivKey)
	if err != nil {
		return err
	}

	contentBytes := buf.Bytes()
	if err := s.fs.WriteFile(contentFileName, contentBytes); err != nil {
		return err
	}

	s.content = append([]byte(nil), contentBytes...)
	s.contentID = append([]byte(nil), cid...)
	s.metadata = meta
	return nil
}

func (s *Store) snapshot() contentSnapshot {
	return contentSnapshot{
		id:     append([]byte(nil), s.contentID...),
		length: int64(len(s.content)),
	}
}

func cloneFiles(files map[string][]byte) map[string]usercontent.File {
	out := make(map[string]usercontent.File, len(files))
	for name, data := range files {
		out[name] = usercontent.File{
			Body: bytes.NewReader(data),
			Size: int64(len(data)),
		}
	}
	return out
}

func newAESBlock(key []byte) cipher.Block {
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return blk
}

func makeXORKeyStream(block cipher.Block) usercontent.XORKeyStreamAt {
	blockSize := block.BlockSize()
	return func(dst, src, iv []byte, offset uint64) {
		if len(dst) != len(src) {
			panic("usercontent: xor buffer length mismatch")
		}
		counter := make([]byte, blockSize)
		copy(counter, iv)
		blocksToSkip := offset / uint64(blockSize)
		addCounter(counter, blocksToSkip)
		buf := make([]byte, blockSize)
		written := 0
		skip := int(offset % uint64(blockSize))
		for written < len(src) {
			block.Encrypt(buf, counter)
			for i := skip; i < blockSize && written < len(src); i++ {
				dst[written] = src[written] ^ buf[i]
				written++
			}
			skip = 0
			addCounter(counter, 1)
		}
	}
}

func addCounter(counter []byte, delta uint64) {
	carry := delta
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(counter[i]) + (carry & 0xff)
		counter[i] = byte(sum)
		carry = carry>>8 + sum>>8
	}
}
