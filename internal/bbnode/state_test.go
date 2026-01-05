package bbnode

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"strconv"
	"sync"
	"testing"
	"testing/fstest"
	"testing/synctest"

	"github.com/starius/barterbackup/internal/bbnode/userstorage"
	"github.com/stretchr/testify/require"
)

type stateTestFS struct {
	fstest.MapFS
}

func newStateTestFS() *stateTestFS {
	return &stateTestFS{MapFS: fstest.MapFS{}}
}

func (m *stateTestFS) ReadFile(name string) ([]byte, error) {
	file, ok := m.MapFS[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), file.Data...), nil
}

func (m *stateTestFS) WriteFile(name string, data []byte) error {
	m.MapFS[name] = &fstest.MapFile{Data: append([]byte(nil), data...), Mode: 0o600}
	return nil
}

func (m *stateTestFS) OpenRead(name string) (userstorage.ReadFile, error) {
	data, err := m.ReadFile(name)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(data)
	return &mockReadFile{ReaderAt: r, size: int64(len(data))}, nil
}

func (m *stateTestFS) OpenWrite(name string) (userstorage.WriteFile, error) {
	var buf bytes.Buffer
	return &mockWriteFile{buf: &buf, commit: func() {
		m.MapFS[name] = &fstest.MapFile{Data: append([]byte(nil), buf.Bytes()...), Mode: 0o600}
	}}, nil
}

func (m *stateTestFS) Remove(name string) error {
	delete(m.MapFS, name)
	return nil
}

func (m *stateTestFS) List() ([]string, error) {
	names := make([]string, 0, len(m.MapFS))
	for n := range m.MapFS {
		names = append(names, n)
	}
	return names, nil
}

func (m *stateTestFS) Rename(oldName, newName string) error {
	f, ok := m.MapFS[oldName]
	if !ok {
		return fs.ErrNotExist
	}
	m.MapFS[newName] = f
	delete(m.MapFS, oldName)
	return nil
}

type mockReadFile struct {
	io.ReaderAt
	size int64
}

func (m *mockReadFile) Size() int64 {
	return m.size
}

func (m *mockReadFile) Close() error {
	return nil
}

type mockWriteFile struct {
	buf    *bytes.Buffer
	closed bool
	commit func()
}

func (m *mockWriteFile) Write(p []byte) (int, error) {
	return m.buf.Write(p)
}

func (m *mockWriteFile) Sync() error {
	return nil
}

func (m *mockWriteFile) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	if m.commit != nil {
		m.commit()
	}
	return nil
}

func TestEventStateConcurrentAccess(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		fsys := newStateTestFS()
		store, err := userstorage.NewStore(fsys, bytes.Repeat([]byte("m"), 32))
		require.NoError(t, err)

		state := newEventState(store)
		t.Cleanup(state.Close)

		ctx := context.Background()

		const workers = 200
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				name := "file-" + strconv.Itoa(i)
				data := []byte(name)

				require.NoError(t, state.SetFile(ctx, name, data))

				files, err := state.ListFiles(ctx)
				require.NoError(t, err)
				require.Contains(t, files, name)

				fetched, err := state.GetFile(ctx, name)
				require.NoError(t, err)
				require.Equal(t, data, fetched)

				require.NoError(t, state.DeleteFile(ctx, name))

				files, err = state.ListFiles(ctx)
				require.NoError(t, err)
				require.NotContains(t, files, name)
			}()
		}

		wg.Wait()

		files, err := state.ListFiles(ctx)
		require.NoError(t, err)
		require.Empty(t, files)
	})
}
