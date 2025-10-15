package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalStoreSetGetDelete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	master := []byte("local-store-master")

	store, err := newLocalStore(dir, master)
	require.NoError(t, err)

	require.NoError(t, store.setFile("foo.txt", []byte("secret payload")))

	data, err := store.getFile("foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("secret payload"), data)

	blob, err := os.ReadFile(filepath.Join(dir, storageFileName))
	require.NoError(t, err)
	require.NotContains(t, string(blob), "secret payload")

	reloaded, err := newLocalStore(dir, master)
	require.NoError(t, err)

	reloadedData, err := reloaded.getFile("foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("secret payload"), reloadedData)

	require.NoError(t, reloaded.deleteFile("foo.txt"))

	_, err = reloaded.getFile("foo.txt")
	require.ErrorIs(t, err, ErrFileNotFound)

	require.ErrorIs(t, reloaded.deleteFile("foo.txt"), ErrFileNotFound)

	blobAfterDelete, err := os.ReadFile(filepath.Join(dir, storageFileName))
	require.NoError(t, err)
	require.NotContains(t, string(blobAfterDelete), "secret payload")
}

func TestLocalStoreEmptyDirError(t *testing.T) {
	t.Parallel()

	_, err := newLocalStore("", []byte("master"))
	require.Error(t, err)
}
