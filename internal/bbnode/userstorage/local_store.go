package userstorage

import (
	"bytes"
	"context"
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
	fs         Filesystem
	files      map[string][]byte
	metadata   *storedpb.Metadata
	content    []byte
	contentID  []byte
	contentKey []byte
	filesKey   []byte
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
	filesKey, err := keys.DeriveKey(master, "usercontent/files", 32)
	if err != nil {
		return nil, err
	}
	store := &Store{
		fs:         fsys,
		files:      make(map[string][]byte),
		contentKey: contentKey,
		filesKey:   filesKey,
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
	uc, err := usercontent.ParseContentFile(bytes.NewReader(data), s.contentKey, s.filesKey)
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
	meta, err := usercontent.MetadataFromUserContent(usercontent.UserContent{
		CreatedAt: uc.CreatedAt,
		Files:     cloneFiles(s.files),
		Peers:     uc.Peers,
	})
	if err != nil {
		return err
	}
	s.metadata = meta
	s.content = bytes.Clone(data)
	s.contentID, err = usercontent.MakeContentID(uc.CreatedAt, s.contentKey)
	return err
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
	uc := usercontent.UserContent{
		CreatedAt: time.Now(),
		Files:     cloneFiles(s.files),
	}
	if s.metadata != nil {
		uc.Peers = s.metadata.GetPeers()
	}

	var buf bytes.Buffer
	if err := usercontent.WriteContentFile(&buf, uc, s.contentKey, s.filesKey); err != nil {
		return err
	}

	meta, err := usercontent.MetadataFromUserContent(uc)
	if err != nil {
		return err
	}
	contentID, err := usercontent.MakeContentID(uc.CreatedAt, s.contentKey)
	if err != nil {
		return err
	}

	contentBytes := buf.Bytes()
	if err := s.fs.WriteFile(contentFileName, contentBytes); err != nil {
		return err
	}

	s.content = append([]byte(nil), contentBytes...)
	s.contentID = contentID
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
