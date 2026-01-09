package userstorage

import (
	"bytes"
	"errors"
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

// OpenRead opens a file for random-access reads.
func (m *MapFilesystem) OpenRead(name string) (ReadFile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &mapReadHandle{
		reader: bytes.NewReader(data),
		size:   int64(len(data)),
	}, nil
}

// OpenWrite opens a file for buffered writes.
func (m *MapFilesystem) OpenWrite() (WriteFile, error) {
	return &mapWriteHandle{
		mu:    &m.mu,
		files: m.files,
	}, nil
}

// Remove deletes a named file.
func (m *MapFilesystem) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[name]; !ok {
		return fs.ErrNotExist
	}
	delete(m.files, name)
	return nil
}

// List returns all stored filenames.
func (m *MapFilesystem) List() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.files))
	for name := range m.files {
		names = append(names, name)
	}
	return names, nil
}

type mapReadHandle struct {
	reader *bytes.Reader
	size   int64
}

// mapReadHandle implements ReadFile for in-memory data.
// ReadAt proxies random-access reads to the underlying buffer.
func (h *mapReadHandle) ReadAt(p []byte, off int64) (int, error) {
	return h.reader.ReadAt(p, off)
}

// Size returns the total length of the buffer.
func (h *mapReadHandle) Size() int64 {
	return h.size
}

// Close is a no-op for the in-memory handle.
func (h *mapReadHandle) Close() error {
	return nil
}

type mapWriteHandle struct {
	mu     *sync.RWMutex
	files  map[string][]byte
	buf    bytes.Buffer
	closed bool
}

// mapWriteHandle implements WriteFile for in-memory data.
// Write appends data to the in-memory buffer.
func (h *mapWriteHandle) Write(p []byte) (int, error) {
	return h.buf.Write(p)
}

// Finalize publishes or discards the buffered data.
func (h *mapWriteHandle) Finalize(name string) error {
	if h.closed {
		return errors.New("mapfs: finalize after close")
	}
	if name == "" {
		return errors.New("mapfs: empty name")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[name] = append([]byte(nil), h.buf.Bytes()...)
	h.closed = true
	return nil
}

func (h *mapWriteHandle) Abort() error {
	h.closed = true
	return nil
}
