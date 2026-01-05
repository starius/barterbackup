package userstorage

import (
	"context"
	"io"
	"testing"

	"github.com/starius/barterbackup/internal/keys"
	"github.com/stretchr/testify/require"
)

// readAll pulls an entire file into memory for assertions.
func readAll(t *testing.T, fsys Filesystem, name string) []byte {
	t.Helper()
	reader, err := fsys.OpenRead(name)
	require.NoError(t, err)
	defer reader.Close()

	buf := make([]byte, reader.Size())
	n, err := reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		require.NoError(t, err)
	}
	require.Equal(t, int(reader.Size()), n)
	return buf
}

// TestStoreSetGetDelete exercises the store lifecycle operations.
func TestStoreSetGetDelete(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	master := keys.DeriveMasterPriv("local-store-master")

	store, err := NewStore(fsys, master)
	require.NoError(t, err)

	require.NoError(t, store.SetFile(context.Background(), "foo.txt", []byte("secret payload")))

	data, err := store.GetFile(t.Context(), "foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("secret payload"), data)

	blob := readAll(t, fsys, contentFileName)
	require.NotContains(t, string(blob), "secret payload")

	reloaded, err := NewStore(fsys, master)
	require.NoError(t, err)

	reloadedData, err := reloaded.GetFile(t.Context(), "foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("secret payload"), reloadedData)
	require.Equal(t, []string{"foo.txt"}, mustList(t, reloaded))

	require.NoError(t, reloaded.DeleteFile(t.Context(), "foo.txt"))

	_, err = reloaded.GetFile(t.Context(), "foo.txt")
	require.ErrorIs(t, err, ErrFileNotFound)
	require.Empty(t, mustList(t, reloaded))

	blobAfterDelete := readAll(t, fsys, contentFileName)
	require.NotContains(t, string(blobAfterDelete), "secret payload")
}

// TestStoreEmptyFilesystemError ensures nil filesystem is rejected.
func TestStoreEmptyFilesystemError(t *testing.T) {
	t.Parallel()

	_, err := NewStore(nil, []byte("master"))
	require.Error(t, err)
}

// TestShortMasterRejected ensures low-entropy master keys fail.
func TestShortMasterRejected(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	_, err := NewStore(fsys, []byte("short"))
	require.Error(t, err)
}

// mustList wraps ListFiles and fails the test on error.
func mustList(t *testing.T, store *Store) []string {
	t.Helper()
	names, err := store.ListFiles(t.Context())
	require.NoError(t, err)
	return names
}
