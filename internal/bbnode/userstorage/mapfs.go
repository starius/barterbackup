package userstorage

import (
	"io/fs"
	"sync"
)

// MapFilesystem is an in-memory Filesystem implementation for tests.
type MapFilesystem struct {
	mu    sync.RWMutex
	files map[string][]byte
}

func NewMapFilesystem() *MapFilesystem {
	return &MapFilesystem{files: make(map[string][]byte)}
}

func (m *MapFilesystem) ReadFile(name string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *MapFilesystem) WriteFile(name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[name] = append([]byte(nil), data...)
	return nil
}
