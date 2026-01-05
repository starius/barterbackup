package userstorage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/starius/aesctrat"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
	"github.com/starius/barterbackup/storedpb"
)

// contentFileName is the on-disk filename for persisted content.
const contentFileName = "content.bin"

// Filesystem abstracts persistent storage operations for user data using streams.
type Filesystem interface {
	OpenRead(name string) (ReadFile, error)
	OpenWrite(name string) (WriteFile, error)
}

// ReadFile provides random access to a persisted object.
type ReadFile interface {
	io.ReaderAt
	Size() int64
	Close() error
}

// WriteFile allows streaming writes with explicit fsync.
type WriteFile interface {
	io.Writer
	Sync() error
	Close() error
}

// ErrFileNotFound signals missing files in storage.
var ErrFileNotFound = errors.New("file not found")

// contentSnapshot captures responder content metadata for quick access.
type contentSnapshot struct {
	// id is the current content identifier.
	id []byte

	// length is the byte length of the persisted content blob.
	length int64
}

// Store maintains the encrypted user content metadata and files on disk.
type Store struct {
	// fs is the backing filesystem implementation.
	fs Filesystem

	// files holds the file bodies keyed by name.
	files map[string]usercontent.File

	// contentID is the last persisted content identifier.
	contentID []byte

	// contentSeal seals content IDs.
	contentSeal usercontent.SealFunc

	// contentOpen opens content IDs.
	contentOpen usercontent.OpenFunc

	// metadataSeal seals metadata blobs.
	metadataSeal usercontent.SealFunc

	// metadataOpen opens metadata blobs.
	metadataOpen usercontent.OpenFunc

	// xor is the per-file keystream function.
	xor usercontent.XORKeyStreamAt

	// peers are the last persisted peers.
	peers []*storedpb.Peer

	// contentLen is the byte length of the stored content blob.
	contentLen int64

	// contentRead keeps the current content file open for random access.
	contentRead ReadFile
}

// NewStore loads persisted state from the provided filesystem.
func NewStore(fsys Filesystem, master []byte) (*Store, error) {
	if fsys == nil {
		return nil, errors.New("filesystem is nil")
	}
	if len(master) < 32 {
		return nil, errors.New("master key too short")
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
	contentSeal, contentOpen, err := usercontent.NewAEAD(contentKey)
	if err != nil {
		return nil, err
	}
	metadataSeal, metadataOpen, err := usercontent.NewAEAD(metaKey)
	if err != nil {
		return nil, err
	}
	xor := aesctrat.NewAesCtr(fileKey).XORKeyStreamAt

	store := &Store{
		fs:           fsys,
		files:        make(map[string]usercontent.File),
		contentSeal:  contentSeal,
		contentOpen:  contentOpen,
		metadataSeal: metadataSeal,
		metadataOpen: metadataOpen,
		xor:          xor,
	}
	if err := store.load(); err != nil {
		return nil, err
	}

	return store, nil
}

// load hydrates the in-memory store from persisted content if present.
func (s *Store) load() error {
	reader, err := s.fs.OpenRead(contentFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	return s.replaceContent(reader)
}

// SetFile persists or updates a file.
func (s *Store) SetFile(_ context.Context, name string, data []byte) error {
	if name == "" {
		return errors.New("file name is empty")
	}
	s.files[name] = usercontent.File{
		Body: bytes.NewReader(data),
		Size: int64(len(data)),
	}
	return s.persist()
}

// GetFile retrieves a persisted file by name.
func (s *Store) GetFile(_ context.Context, name string) ([]byte, error) {
	data, ok := s.files[name]
	if !ok {
		return nil, ErrFileNotFound
	}
	buf := make([]byte, data.Size)
	read := int64(0)
	for read < data.Size {
		n, err := data.Body.ReadAt(buf[read:], read)
		read += int64(n)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if err == io.EOF {
			break
		}
	}
	if read != data.Size {
		return nil, errors.New("short read")
	}
	return buf, nil
}

// DeleteFile removes a file from persistent state.
func (s *Store) DeleteFile(_ context.Context, name string) error {
	if _, ok := s.files[name]; !ok {
		return ErrFileNotFound
	}
	delete(s.files, name)
	return s.persist()
}

// ListFiles returns the sorted list of file names.
func (s *Store) ListFiles(_ context.Context) ([]string, error) {
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, nil
}

// persist encodes the current state to the backing filesystem.
func (s *Store) persist() error {
	now := time.Now()
	uc := usercontent.UserContent{
		CreatedAt: now,
		Files:     s.files,
	}
	if len(s.peers) > 0 {
		uc.Peers = append([]*storedpb.Peer(nil), s.peers...)
	}

	writer, err := s.fs.OpenWrite(contentFileName)
	if err != nil {
		return err
	}
	defer writer.Close()

	cw := &countingWriter{w: writer}
	cid, err := usercontent.WriteContentFile(
		cw, uc, s.contentSeal, s.metadataSeal, s.xor,
	)
	if err != nil {
		_ = writer.Close()
		return err
	}

	if err := writer.Sync(); err != nil {
		_ = writer.Close()
		return err
	}
	s.contentLen = cw.n
	if err := writer.Close(); err != nil {
		return err
	}

	reader, err := s.fs.OpenRead(contentFileName)
	if err != nil {
		return err
	}
	if err := s.replaceContent(reader); err != nil {
		return err
	}

	s.contentID = append([]byte(nil), cid...)

	return nil
}

// snapshot captures the current content ID and length.
func (s *Store) snapshot() contentSnapshot {
	return contentSnapshot{
		id:     append([]byte(nil), s.contentID...),
		length: s.contentLen,
	}
}

// countingWriter wraps an io.Writer to track bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

// Write proxies to the underlying writer and accumulates the byte count.
func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

// replaceContent swaps in a new content reader and rebuilds in-memory state.
func (s *Store) replaceContent(reader ReadFile) error {
	uc, cid, err := usercontent.ParseContentFile(
		reader, s.contentOpen, s.metadataOpen, s.xor,
	)
	if err != nil {
		_ = reader.Close()
		return err
	}
	if s.contentRead != nil {
		_ = s.contentRead.Close()
	}
	s.contentRead = reader
	s.contentLen = reader.Size()
	s.files = uc.Files
	s.contentID = append([]byte(nil), cid...)
	s.peers = append([]*storedpb.Peer(nil), uc.Peers...)

	return nil
}
