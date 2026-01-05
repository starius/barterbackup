package userstorage

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/starius/aesctrat"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
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

	blob := readAll(t, fsys, firstContentFile(t, fsys))
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

	blobAfterDelete := readAll(t, fsys, firstContentFile(t, fsys))
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

func TestLoadChoosesNewerAndDeletesOlder(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	master := keys.DeriveMasterPriv("choose-newer")

	writeContentFile(t, fsys, master, time.Unix(10, 0), "old.txt", []byte("old"))
	newCID, newName := writeContentFile(t, fsys, master, time.Unix(20, 0), "new.txt", []byte("new"))

	store, err := NewStore(fsys, master)
	require.NoError(t, err)
	require.Equal(t, newCID, store.CurrentContentID())

	names, err := fsys.List()
	require.NoError(t, err)
	require.Equal(t, []string{newName}, names)
}

func TestLoadAmbiguousMultipleValidFails(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	master := keys.DeriveMasterPriv("ambiguous")

	writeContentFile(t, fsys, master, time.Unix(10, 0), "a", []byte("a"))
	writeContentFile(t, fsys, master, time.Unix(20, 0), "b", []byte("b"))
	writeContentFile(t, fsys, master, time.Unix(30, 0), "c", []byte("c"))

	_, err := NewStore(fsys, master)
	require.Error(t, err)
}

// TestRecoveryInfoSummaries ensures recovery output lists expected files.
func TestRecoveryInfoSummaries(t *testing.T) {
	t.Parallel()

	master := keys.DeriveMasterPriv("recovery")

	t.Run("two-valid-recommend-newest", func(t *testing.T) {
		fsys := NewMapFilesystem()
		writeContentFile(t, fsys, master, time.Unix(10, 0), "a", []byte("a"))
		_, newName := writeContentFile(t, fsys, master, time.Unix(20, 0), "b", []byte("b"))

		store := bareStore(t, fsys, master)
		info := store.RecoveryInfo()
		require.Contains(t, info, "Recommendation: keep "+newName)
	})

	t.Run("valid-and-invalid", func(t *testing.T) {
		fsys := NewMapFilesystem()
		_, name := writeContentFile(t, fsys, master, time.Unix(10, 0), "a", []byte("a"))
		_, badName := writeContentFile(t, fsys, master, time.Unix(20, 0), "b", []byte("b"))
		truncateLastByte(t, fsys, badName)

		store := bareStore(t, fsys, master)
		info := store.RecoveryInfo()
		require.Contains(t, info, name)
		require.Contains(t, info, badName)
		require.Contains(t, info, "invalid")
		require.Contains(t, info, "manual intervention")
	})

	t.Run("three-valid", func(t *testing.T) {
		fsys := NewMapFilesystem()
		writeContentFile(t, fsys, master, time.Unix(10, 0), "a", []byte("a"))
		writeContentFile(t, fsys, master, time.Unix(20, 0), "b", []byte("b"))
		writeContentFile(t, fsys, master, time.Unix(30, 0), "c", []byte("c"))

		store := bareStore(t, fsys, master)
		info := store.RecoveryInfo()
		require.Contains(t, info, "manual intervention")
	})
}

// TestFilenameContentIDMismatchFails ensures mismatched filename/CID is rejected.
func TestFilenameContentIDMismatchFails(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	master := keys.DeriveMasterPriv("mismatch")

	store, err := NewStore(fsys, master)
	require.NoError(t, err)

	store.now = func() time.Time { return time.Unix(10, 0) }
	require.NoError(t, store.SetFile(t.Context(), "a.txt", []byte("v1")))
	firstName := currentContentName(t, fsys)

	_, secondName := writeContentFile(t, fsys, master, time.Unix(20, 0), "a.txt", []byte("v2"))
	require.NotEqual(t, firstName, secondName)

	// Corrupt: rename newer content to the old filename, so CID implied by name mismatches body.
	require.NoError(t, fsys.Remove(firstName))
	require.NoError(t, fsys.Rename(secondName, firstName))

	_, err = NewStore(fsys, master)
	require.Error(t, err)
}

// mustList wraps ListFiles and fails the test on error.
func mustList(t *testing.T, store *Store) []string {
	t.Helper()
	names, err := store.ListFiles(t.Context())
	require.NoError(t, err)
	return names
}

// writeContentFile produces a single-file content blob at the given time.
func writeContentFile(t *testing.T, fsys Filesystem, master []byte, createdAt time.Time, name string, data []byte) ([]byte, string) {
	t.Helper()
	contentKey, err := keys.DeriveKey(master, "usercontent/content-id", 32)
	require.NoError(t, err)
	metaKey, err := keys.DeriveKey(master, "usercontent/metadata", 32)
	require.NoError(t, err)
	fileKey, err := keys.DeriveKey(master, "usercontent/files", 32)
	require.NoError(t, err)

	contentSeal, _, err := usercontent.NewAEAD(contentKey)
	require.NoError(t, err)
	metadataSeal, _, err := usercontent.NewAEAD(metaKey)
	require.NoError(t, err)
	xor := aesctrat.NewAesCtr(fileKey).XORKeyStreamAt

	uc := usercontent.UserContent{
		CreatedAt: createdAt,
		Files: map[string]usercontent.File{
			name: {
				Body: bytes.NewReader(data),
				Size: int64(len(data)),
			},
		},
	}

	var buf bytes.Buffer
	cid, err := usercontent.WriteContentFile(&buf, uc, contentSeal, metadataSeal, xor)
	require.NoError(t, err)

	finalName := contentFileNameFor(cid)
	w, err := fsys.OpenWrite(finalName)
	require.NoError(t, err)
	_, err = w.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, w.Sync())
	require.NoError(t, w.Close())

	return cid, finalName
}

// truncateLastByte removes the last byte from a stored content file.
func truncateLastByte(t *testing.T, fsys Filesystem, name string) {
	t.Helper()
	reader, err := fsys.OpenRead(name)
	require.NoError(t, err)
	defer reader.Close()

	data := make([]byte, reader.Size())
	n, err := reader.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		require.NoError(t, err)
	}
	data = data[:n]
	require.Greater(t, len(data), 0)

	require.NoError(t, fsys.Remove(name))
	w, err := fsys.OpenWrite(name)
	require.NoError(t, err)
	_, err = w.Write(data[:len(data)-1])
	require.NoError(t, err)
	require.NoError(t, w.Sync())
	require.NoError(t, w.Close())
}

// bareStore constructs a Store with provided primitives for testing.
func bareStore(t *testing.T, fsys Filesystem, master []byte) *Store {
	t.Helper()
	contentKey, err := keys.DeriveKey(master, "usercontent/content-id", 32)
	require.NoError(t, err)
	metaKey, err := keys.DeriveKey(master, "usercontent/metadata", 32)
	require.NoError(t, err)
	fileKey, err := keys.DeriveKey(master, "usercontent/files", 32)
	require.NoError(t, err)

	contentSeal, contentOpen, err := usercontent.NewAEAD(contentKey)
	require.NoError(t, err)
	metadataSeal, metadataOpen, err := usercontent.NewAEAD(metaKey)
	require.NoError(t, err)
	xor := aesctrat.NewAesCtr(fileKey).XORKeyStreamAt

	return &Store{
		fs:           fsys,
		files:        make(map[string]usercontent.File),
		contentSeal:  contentSeal,
		contentOpen:  contentOpen,
		metadataSeal: metadataSeal,
		metadataOpen: metadataOpen,
		xor:          xor,
		now:          time.Now,
	}
}

// firstContentFile returns the first content file found in the filesystem.
func firstContentFile(t *testing.T, fsys Filesystem) string {
	t.Helper()
	names, err := fsys.List()
	require.NoError(t, err)
	for _, name := range names {
		if strings.HasPrefix(name, contentFilePrefix) && strings.HasSuffix(name, ".bin") {
			return name
		}
	}
	t.Fatalf("no content files found")
	return ""
}

// currentContentName returns the only content file name in the filesystem.
func currentContentName(t *testing.T, fsys Filesystem) string {
	t.Helper()
	return firstContentFile(t, fsys)
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

// List delegates to the underlying filesystem.
func (f *failingFS) List() ([]string, error) {
	return f.delegate.List()
}

// Remove delegates to the underlying filesystem.
func (f *failingFS) Remove(name string) error {
	return f.delegate.Remove(name)
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
