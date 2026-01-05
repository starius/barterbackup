package userstorage

import (
	"bytes"
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
func (m *MapFilesystem) OpenWrite(name string) (WriteFile, error) {
	return &mapWriteHandle{
		mu:    &m.mu,
		name:  name,
		files: m.files,
	}, nil
}

// Rename swaps an existing entry to a new name.
func (m *MapFilesystem) Rename(oldName, newName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[oldName]
	if !ok {
		return fs.ErrNotExist
	}
	m.files[newName] = append([]byte(nil), data...)
	delete(m.files, oldName)
	return nil
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
	name   string
	files  map[string][]byte
	buf    bytes.Buffer
	closed bool
}

// mapWriteHandle implements WriteFile for in-memory data.
// Write appends data to the in-memory buffer.
func (h *mapWriteHandle) Write(p []byte) (int, error) {
	return h.buf.Write(p)
}

// Sync commits the buffered data to the map.
func (h *mapWriteHandle) Sync() error {
	if h.closed {
		return nil
	}
	h.mu.Lock()
	h.files[h.name] = append([]byte(nil), h.buf.Bytes()...)
	h.mu.Unlock()
	return nil
}

// Close finalizes the write and saves the buffer.
func (h *mapWriteHandle) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	h.mu.Lock()
	h.files[h.name] = append([]byte(nil), h.buf.Bytes()...)
	h.mu.Unlock()
	return nil
}
