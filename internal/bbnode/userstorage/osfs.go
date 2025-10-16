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

func (fsys *OSFilesystem) ReadFile(name string) ([]byte, error) {
	path := filepath.Join(fsys.root, filepath.Clean(name))
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	return data, nil
}

func (fsys *OSFilesystem) WriteFile(name string, data []byte) error {
	if err := os.MkdirAll(fsys.root, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(fsys.root, "tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	target := filepath.Join(fsys.root, filepath.Clean(name))
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	return nil
}
