package userstorage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreSetGetDelete(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	master := []byte("local-store-master")

	store, err := NewStore(fsys, master)
	require.NoError(t, err)

	require.NoError(t, store.setFile("foo.txt", []byte("secret payload")))

	data, err := store.getFile("foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("secret payload"), data)

	blob, err := fsys.ReadFile(contentFileName)
	require.NoError(t, err)
	require.NotContains(t, string(blob), "secret payload")

	reloaded, err := NewStore(fsys, master)
	require.NoError(t, err)

	reloadedData, err := reloaded.getFile("foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("secret payload"), reloadedData)
	require.Equal(t, []string{"foo.txt"}, reloaded.listFiles())

	require.NoError(t, reloaded.deleteFile("foo.txt"))

	_, err = reloaded.getFile("foo.txt")
	require.ErrorIs(t, err, ErrFileNotFound)
	require.Empty(t, reloaded.listFiles())

	blobAfterDelete, err := fsys.ReadFile(contentFileName)
	require.NoError(t, err)
	require.NotContains(t, string(blobAfterDelete), "secret payload")
}

func TestStoreEmptyFilesystemError(t *testing.T) {
	t.Parallel()

	_, err := NewStore(nil, []byte("master"))
	require.Error(t, err)
}
