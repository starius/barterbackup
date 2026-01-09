package userstorage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
		closeErr := f.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("stat error: %v (close error: %w)",
				err, closeErr)
		}
		return nil, err
	}
	return &osReadHandle{
		File: f,
		size: info.Size(),
	}, nil
}

// OpenWrite truncates or creates a file for streaming writes. The file is not
// visible under the final name until Finalize is called.
func (fsys *OSFilesystem) OpenWrite() (WriteFile, error) {
	f, err := os.CreateTemp(fsys.root, ".tmp-*")
	if err != nil {
		return nil, err
	}
	return &osWriteHandle{File: f, root: fsys.root}, nil
}

// Remove deletes a named file.
func (fsys *OSFilesystem) Remove(name string) error {
	path := filepath.Join(fsys.root, name)
	return os.Remove(path)
}

// List returns filenames in the root directory.
func (fsys *OSFilesystem) List() ([]string, error) {
	entries, err := os.ReadDir(fsys.root)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
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
	root      string
	finalName string
	closed    bool
}

// Finalize flushes data, makes it read-only, and renames into place. Empty name discards.
func (h *osWriteHandle) Finalize(name string) error {
	if h.closed {
		return errors.New("osfs: finalize after close")
	}
	if name == "" {
		_ = os.Remove(h.Name())
		_ = h.Close()
		h.closed = true
		return errors.New("osfs: empty final name")
	}
	h.finalName = name
	if err := h.Sync(); err != nil {
		_ = h.Close()
		_ = os.Remove(h.Name())
		return err
	}
	if err := h.Close(); err != nil {
		_ = os.Remove(h.Name())
		return err
	}
	h.closed = true
	finalPath := filepath.Join(h.root, h.finalName)
	if err := os.Rename(h.Name(), finalPath); err != nil {
		_ = os.Remove(h.Name())
		return err
	}
	if err := os.Chmod(finalPath, 0o400); err != nil {
		return err
	}
	return nil
}

// Abort discards the temp file.
func (h *osWriteHandle) Abort() error {
	_ = h.Close()
	return os.Remove(h.Name())
}
