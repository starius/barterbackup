package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoragePersistenceAndEncryption(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	master := []byte("master-key")

	store, err := New(dir, master)
	require.NoError(t, err)

	store.Start(ctx)

	require.NoError(t, store.SetFile(ctx, "note.txt", []byte("hello world")))

	names, err := store.ListFiles(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"note.txt"}, names)

	data, err := store.GetFile(ctx, "note.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), data)

	blob, err := os.ReadFile(filepath.Join(dir, "content.bin"))
	require.NoError(t, err)
	require.NotContains(t, string(blob), "hello world")

	cancel()
	store.WaitForShutdown()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	reloaded, err := New(dir, master)
	require.NoError(t, err)
	reloaded.Start(ctx2)
	defer func() {
		cancel2()
		reloaded.WaitForShutdown()
	}()

	reloadedData, err := reloaded.GetFile(ctx2, "note.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), reloadedData)
}

func TestStorageWrongKeyFails(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	master := []byte("master-key")

	store, err := New(dir, master)
	require.NoError(t, err)
	store.Start(ctx)

	require.NoError(t, store.SetFile(ctx, "note.txt", []byte("secret")))

	cancel()
	store.WaitForShutdown()

	_, err = New(dir, []byte("wrong-key"))
	require.Error(t, err)
}
