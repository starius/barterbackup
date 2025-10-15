package storage

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

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

	require.NoError(t, store.DeleteFile(ctx, "note.txt"))

	_, err = store.GetFile(ctx, "note.txt")
	require.ErrorIs(t, err, ErrFileNotFound)

	names, err = store.ListFiles(ctx)
	require.NoError(t, err)
	require.Empty(t, names)

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

	reloadedNames, err := reloaded.ListFiles(ctx2)
	require.NoError(t, err)
	require.Empty(t, reloadedNames)

	_, err = reloaded.GetFile(ctx2, "note.txt")
	require.ErrorIs(t, err, ErrFileNotFound)
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

func TestStorageConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	master := []byte("concurrent-master")

	store, err := New(dir, master)
	require.NoError(t, err)
	store.Start(ctx)
	defer func() {
		cancel()
		store.WaitForShutdown()
	}()

	randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))
	var mu sync.Mutex
	sleepRand := func() {
		mu.Lock()
		d := time.Duration(randSrc.Int63n(int64(100 * time.Millisecond)))
		mu.Unlock()
		time.Sleep(d)
	}

	const workers = 1000
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := "file-" + strconv.Itoa(i)
			content := []byte(name + "-payload")

			require.NoError(t, store.SetFile(ctx, name, content))
			sleepRand()

			names, err := store.ListFiles(ctx)
			require.NoError(t, err)
			require.Contains(t, names, name)

			data, err := store.GetFile(ctx, name)
			require.NoError(t, err)
			require.Equal(t, content, data)

			sleepRand()

			require.NoError(t, store.DeleteFile(ctx, name))

			names, err = store.ListFiles(ctx)
			require.NoError(t, err)
			require.NotContains(t, names, name)
		}()
	}

	wg.Wait()

	finalNames, err := store.ListFiles(ctx)
	require.NoError(t, err)
	require.Empty(t, finalNames)
}
