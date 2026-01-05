package userstorage

import (
	"errors"
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

	require.NoError(t, store.SetFile(t.Context(), "foo.txt", []byte("secret payload")))

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

// TestAtomicPersistFailureDoesNotClobberExisting ensures failed writes do not replace good data.
func TestAtomicPersistFailureDoesNotClobberExisting(t *testing.T) {
	t.Parallel()

	baseFS := NewMapFilesystem()
	master := keys.DeriveMasterPriv("atomic-master")

	store, err := NewStore(baseFS, master)
	require.NoError(t, err)
	require.NoError(t, store.SetFile(t.Context(), "foo.txt", []byte("v1")))

	failing := &failingFS{delegate: baseFS, failOnce: true}
	storeFail, err := NewStore(failing, master)
	require.NoError(t, err)

	err = storeFail.SetFile(t.Context(), "foo.txt", []byte("v2"))
	require.Error(t, err, "persist should fail and leave prior content intact")

	reloaded, err := NewStore(baseFS, master)
	require.NoError(t, err)

	data, err := reloaded.GetFile(t.Context(), "foo.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("v1"), data)
}

// mustList wraps ListFiles and fails the test on error.
func mustList(t *testing.T, store *Store) []string {
	t.Helper()
	names, err := store.ListFiles(t.Context())
	require.NoError(t, err)
	return names
}

// failingFS injects a write failure on the next write.
type failingFS struct {
	delegate Filesystem
	failOnce bool
}

// OpenRead delegates to the underlying filesystem.
func (f *failingFS) OpenRead(name string) (ReadFile, error) {
	return f.delegate.OpenRead(name)
}

// OpenWrite wraps the writer to inject a single failure.
func (f *failingFS) OpenWrite(name string) (WriteFile, error) {
	w, err := f.delegate.OpenWrite(name)
	if err != nil {
		return nil, err
	}
	return &failingWrite{
		w:       w,
		trigger: &f.failOnce,
	}, nil
}

// Rename delegates to the underlying filesystem.
func (f *failingFS) Rename(oldName, newName string) error {
	return f.delegate.Rename(oldName, newName)
}

// failingWrite injects a failure on the first Write when triggered.
type failingWrite struct {
	w       WriteFile
	trigger *bool
}

// Write injects an error once, then passes through.
func (fw *failingWrite) Write(p []byte) (int, error) {
	if fw.trigger != nil && *fw.trigger {
		*fw.trigger = false
		return 0, errors.New("injected write failure")
	}
	return fw.w.Write(p)
}

// Sync forwards to the underlying writer.
func (fw *failingWrite) Sync() error {
	return fw.w.Sync()
}

// Close forwards to the underlying writer.
func (fw *failingWrite) Close() error {
	return fw.w.Close()
}
