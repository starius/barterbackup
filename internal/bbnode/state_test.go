package bbnode

import (
	"context"
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

func TestEventStateConcurrentAccess(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		fsys := newStateTestFS()
		store, err := userstorage.NewStore(fsys, []byte("master"))
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
