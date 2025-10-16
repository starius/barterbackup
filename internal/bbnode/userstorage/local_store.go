package userstorage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
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

const (
	storageMagicBytes = "BBST"
	storageVersion    = 1
	saltSize          = 32
)

// contentSnapshot captures responder content metadata for quick access.
type contentSnapshot struct {
	id     []byte
	length int64
}

// Store maintains the encrypted user content metadata and files on disk.
type Store struct {
	fs        Filesystem
	master    []byte
	content   []byte
	contentID []byte
	files     map[string][]byte
	metadata  *storedpb.Metadata
}

// NewStore loads persisted state from the provided filesystem.
func NewStore(fsys Filesystem, master []byte) (*Store, error) {
	if fsys == nil {
		return nil, errors.New("filesystem is nil")
	}
	store := &Store{
		fs:     fsys,
		master: append([]byte(nil), master...),
		files:  make(map[string][]byte),
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
		return fmt.Errorf("read storage: %w", err)
	}
	meta, files, err := s.decryptContent(data)
	if err != nil {
		return err
	}
	s.metadata = meta
	s.files = files
	s.content = append([]byte(nil), data...)
	s.contentID = hashContent(data)
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
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt: %w", err)
	}

	metaKey, err := deriveMetadataKey(s.master, salt)
	if err != nil {
		return err
	}
	filesKey, err := deriveFilesKey(s.master, salt)
	if err != nil {
		return err
	}

	fileHeaders := make([]*storedpb.FileHeader, 0, len(s.files))
	names := s.listFiles()
	for _, name := range names {
		data := s.files[name]
		sum := sha256.Sum256(data)
		fileHeaders = append(fileHeaders, &storedpb.FileHeader{
			Name:       name,
			FileLength: int64(len(data)),
			FileSha256: sum[:],
		})
	}

	now := time.Now()
	metadata := &storedpb.Metadata{
		Files: fileHeaders,
	}
	if s.metadata != nil {
		metadata.Peers = s.metadata.GetPeers()
	}
	metadata.MostRecentContent = &storedpb.ContentRevision{
		CreatedAt:   now.Unix(),
		CreatedAtNs: int64(now.Nanosecond()),
	}

	var (
		nonce      []byte
		cipherMeta []byte
		metaLen    int
	)
	for i := 0; i < 5; i++ {
		nonce, cipherMeta, metaLen, err = encryptMetadata(metadata, metaKey)
		if err != nil {
			return err
		}
		if metadata.GetMostRecentContent().GetMetadataAeadLength() == int64(metaLen) {
			break
		}
		metadata.MostRecentContent.MetadataAeadLength = int64(metaLen)
		if i == 4 {
			return errors.New("metadata AEAD length did not stabilize")
		}
	}
	metadata.MostRecentContent.MetadataAeadLength = int64(metaLen)

	fileBlock, err := aes.NewCipher(filesKey)
	if err != nil {
		return fmt.Errorf("file cipher init: %w", err)
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(storageMagicBytes)+1+saltSize+4+len(nonce)+len(cipherMeta)))
	buf.WriteString(storageMagicBytes)
	if err := buf.WriteByte(storageVersion); err != nil {
		return fmt.Errorf("buffer write version: %w", err)
	}
	buf.Write(salt)
	if err := binary.Write(buf, binary.BigEndian, uint32(metaLen)); err != nil {
		return fmt.Errorf("buffer write metadata len: %w", err)
	}
	buf.Write(nonce)
	buf.Write(cipherMeta)

	for _, name := range names {
		data := s.files[name]
		iv, err := deriveFileIV(s.master, salt, name)
		if err != nil {
			return err
		}
		enc := make([]byte, len(data))
		stream := cipher.NewCTR(fileBlock, iv)
		stream.XORKeyStream(enc, data)
		buf.Write(enc)
	}

	content := buf.Bytes()
	if err := s.fs.WriteFile(contentFileName, content); err != nil {
		return fmt.Errorf("write storage: %w", err)
	}

	s.content = append([]byte(nil), content...)
	s.contentID = hashContent(content)
	s.metadata = metadata

	return nil
}

func (s *Store) snapshot() contentSnapshot {
	return contentSnapshot{
		id:     append([]byte(nil), s.contentID...),
		length: int64(len(s.content)),
	}
}

func (s *Store) decryptContent(blob []byte) (*storedpb.Metadata, map[string][]byte, error) {
	r := bytes.NewReader(blob)

	magic := make([]byte, len(storageMagicBytes))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != storageMagicBytes {
		return nil, nil, errors.New("invalid storage magic")
	}

	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, nil, fmt.Errorf("read version: %w", err)
	}
	if version != storageVersion {
		return nil, nil, fmt.Errorf("unsupported storage version %d", version)
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, nil, fmt.Errorf("read salt: %w", err)
	}

	var metadataLen uint32
	if err := binary.Read(r, binary.BigEndian, &metadataLen); err != nil {
		return nil, nil, fmt.Errorf("read metadata length: %w", err)
	}

	if metadataLen < 12 {
		return nil, nil, errors.New("metadata length too small")
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, nil, fmt.Errorf("read metadata nonce: %w", err)
	}

	cipherLen := int(metadataLen) - len(nonce)
	if cipherLen < 0 {
		return nil, nil, errors.New("negative metadata cipher length")
	}
	metaCipher := make([]byte, cipherLen)
	if _, err := io.ReadFull(r, metaCipher); err != nil {
		return nil, nil, fmt.Errorf("read metadata cipher: %w", err)
	}

	metaKey, err := deriveMetadataKey(s.master, salt)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(metaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata GCM init: %w", err)
	}
	metaPlain, err := gcm.Open(nil, nonce, metaCipher, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata decrypt: %w", err)
	}
	var metadata storedpb.Metadata
	if err := proto.Unmarshal(metaPlain, &metadata); err != nil {
		return nil, nil, fmt.Errorf("metadata decode: %w", err)
	}

	filesKey, err := deriveFilesKey(s.master, salt)
	if err != nil {
		return nil, nil, err
	}
	fileBlock, err := aes.NewCipher(filesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("file cipher init: %w", err)
	}

	files := make(map[string][]byte, len(metadata.GetFiles()))
	for _, fh := range metadata.GetFiles() {
		length := fh.GetFileLength()
		if length < 0 {
			return nil, nil, fmt.Errorf("negative file length for %q", fh.GetName())
		}
		enc := make([]byte, length)
		if _, err := io.ReadFull(r, enc); err != nil {
			return nil, nil, fmt.Errorf("read encrypted file %q: %w", fh.GetName(), err)
		}
		iv, err := deriveFileIV(s.master, salt, fh.GetName())
		if err != nil {
			return nil, nil, err
		}
		plain := make([]byte, length)
		stream := cipher.NewCTR(fileBlock, iv)
		stream.XORKeyStream(plain, enc)

		sum := sha256.Sum256(plain)
		if !bytes.Equal(sum[:], fh.GetFileSha256()) {
			return nil, nil, fmt.Errorf("file %q hash mismatch", fh.GetName())
		}
		files[fh.GetName()] = plain
	}

	return &metadata, files, nil
}

func encryptMetadata(metadata *storedpb.Metadata, key []byte) ([]byte, []byte, int, error) {
	plain, err := proto.Marshal(metadata)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("metadata marshal: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("metadata cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("metadata GCM init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, 0, fmt.Errorf("metadata nonce: %w", err)
	}
	out := gcm.Seal(nil, nonce, plain, nil)
	metaLen := len(nonce) + len(out)
	return nonce, out, metaLen, nil
}

func deriveMetadataKey(master, salt []byte) ([]byte, error) {
	return keys.DeriveKey(master, "bbnode/metadata:"+hex.EncodeToString(salt), 32)
}

func deriveFilesKey(master, salt []byte) ([]byte, error) {
	return keys.DeriveKey(master, "bbnode/files:"+hex.EncodeToString(salt), 32)
}

func deriveFileIV(master []byte, salt []byte, name string) ([]byte, error) {
	return keys.DeriveKey(master, "bbnode/file-iv:"+hex.EncodeToString(salt)+":"+name, aes.BlockSize)
}

func hashContent(data []byte) []byte {
	sum := sha256.Sum256(data)
	return append([]byte(nil), sum[:]...)
}
