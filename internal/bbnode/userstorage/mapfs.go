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

func (m *MapFilesystem) OpenWrite(name string) (WriteFile, error) {
	return &mapWriteHandle{
		mu:    &m.mu,
		name:  name,
		files: m.files,
	}, nil
}

type mapReadHandle struct {
	reader *bytes.Reader
	size   int64
}

func (h *mapReadHandle) ReadAt(p []byte, off int64) (int, error) {
	return h.reader.ReadAt(p, off)
}

func (h *mapReadHandle) Size() int64 {
	return h.size
}

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

func (h *mapWriteHandle) Write(p []byte) (int, error) {
	return h.buf.Write(p)
}

func (h *mapWriteHandle) Sync() error {
	if h.closed {
		return nil
	}
	h.mu.Lock()
	h.files[h.name] = append([]byte(nil), h.buf.Bytes()...)
	h.mu.Unlock()
	return nil
}

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
