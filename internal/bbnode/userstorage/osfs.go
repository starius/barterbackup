package userstorage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// OSFilesystem implements Filesystem using an on-disk directory.
type OSFilesystem struct {
	root string
}

// NewOSFilesystem prepares an OS-backed filesystem rooted at dir.
func NewOSFilesystem(dir string) (*OSFilesystem, error) {
	if dir == "" {
		return nil, errors.New("storage dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &OSFilesystem{root: dir}, nil
}

// OpenRead opens a file for random-access reads.
func (fsys *OSFilesystem) OpenRead(name string) (ReadFile, error) {
	path := filepath.Join(fsys.root, name)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &osReadHandle{
		File: f,
		size: info.Size(),
	}, nil
}

// OpenWrite truncates or creates a file for streaming writes.
func (fsys *OSFilesystem) OpenWrite(name string) (WriteFile, error) {
	path := filepath.Join(fsys.root, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &osWriteHandle{File: f}, nil
}

// Rename atomically renames a file within the root.
func (fsys *OSFilesystem) Rename(oldName, newName string) error {
	oldPath := filepath.Join(fsys.root, oldName)
	newPath := filepath.Join(fsys.root, newName)
	return os.Rename(oldPath, newPath)
}

// osReadHandle implements ReadFile on top of an *os.File.
type osReadHandle struct {
	*os.File
	size int64
}

// Size returns the file length.
func (h *osReadHandle) Size() int64 {
	return h.size
}

// osWriteHandle implements WriteFile on top of an *os.File.
type osWriteHandle struct {
	*os.File
}

// Sync flushes the file contents to stable storage.
func (h *osWriteHandle) Sync() error {
	return h.File.Sync()
}
