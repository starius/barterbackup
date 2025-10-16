package userstorage

import (
	"errors"
	"io/fs"
	"os"
)

// OSFilesystem implements Filesystem using an os.Root-backed directory.
type OSFilesystem struct {
	root *os.Root
}

// NewOSFilesystem prepares an OS-backed filesystem rooted at dir.
func NewOSFilesystem(dir string) (*OSFilesystem, error) {
	if dir == "" {
		return nil, errors.New("storage dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &OSFilesystem{root: root}, nil
}

func (fsys *OSFilesystem) ReadFile(name string) ([]byte, error) {
	data, err := fsys.root.ReadFile(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	return data, nil
}

func (fsys *OSFilesystem) WriteFile(name string, data []byte) error {
	return fsys.root.WriteFile(name, data, 0o600)
}
