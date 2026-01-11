package userstorage

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
	"github.com/stretchr/testify/require"
	"testing/synctest"
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

	synctest.Test(t, func(t *testing.T) {
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

		err = reloaded.DeleteFile(t.Context(), "foo.txt")
		require.Error(t, err)

		_, err = reloaded.GetFile(t.Context(), "foo.txt")
		require.NoError(t, err)
		require.Equal(t, []string{"foo.txt"}, mustList(t, reloaded))
	})
}

// TestForeignContentIgnored ensures undecipherable content files are skipped, not treated as errors.
func TestForeignContentIgnored(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	// Write a foreign content file with a name that cannot be parsed as our content ID.
	w, err := fsys.OpenWrite()
	require.NoError(t, err)
	_, err = w.Write([]byte("data"))
	require.NoError(t, err)
	require.NoError(t, w.Finalize("foreign"))

	master := keys.DeriveMasterPriv("foreign-ignore")
	store, err := NewStore(fsys, master)
	require.NoError(t, err)
	require.Empty(t, store.CurrentContentID())

	// Subsequent writes should work.
	require.NoError(t, store.SetFile(t.Context(), "a.txt", []byte("payload")))
	require.NotEmpty(t, store.CurrentContentID())
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

	synctest.Test(t, func(t *testing.T) {
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
	})
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
		info, err := store.RecoveryInfo()
		require.NoError(t, err)
		require.Contains(t, info, "Recommendation: keep "+newName)
	})

	t.Run("valid-and-invalid", func(t *testing.T) {
		fsys := NewMapFilesystem()
		_, name := writeContentFile(t, fsys, master, time.Unix(10, 0), "a", []byte("a"))
		_, badName := writeContentFile(t, fsys, master, time.Unix(20, 0), "b", []byte("b"))
		truncateLastByte(t, fsys, badName)

		store := bareStore(t, fsys, master)
		info, err := store.RecoveryInfo()
		require.NoError(t, err)
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
		info, err := store.RecoveryInfo()
		require.NoError(t, err)
		require.Contains(t, info, "manual intervention")
	})
}

// TestFilenameContentIDMismatchFails ensures mismatched filename/CID is rejected.
func TestFilenameContentIDMismatchFails(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		fsys := NewMapFilesystem()
		master := keys.DeriveMasterPriv("mismatch")

		store, err := NewStore(fsys, master)
		require.NoError(t, err)

		require.NoError(t, store.SetFile(t.Context(), "a.txt", []byte("v1")))
		firstName := currentContentName(t, fsys)

		_, secondName := writeContentFile(t, fsys, master, time.Unix(20, 0), "a.txt", []byte("v2"))
		require.NotEqual(t, firstName, secondName)

		// Corrupt: rename newer content to the old filename, so CID implied by name mismatches body.
		// Copy newer content body into the old filename to mismatch CID/body.
		reader, err := fsys.OpenRead(secondName)
		require.NoError(t, err)
		data := make([]byte, reader.Size())
		_, err = reader.ReadAt(data, 0)
		require.NoError(t, err)
		require.NoError(t, reader.Close())

		require.NoError(t, fsys.Remove(firstName))
		w, err := fsys.OpenWrite()
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
		require.NoError(t, w.Finalize(firstName))

		_, err = NewStore(fsys, master)
		require.Error(t, err)
	})
}

// TestPeerMetadataSidecar ensures peer metadata is persisted without rewriting content.
func TestPeerMetadataSidecar(t *testing.T) {
	t.Parallel()

	fsys := NewMapFilesystem()
	master := keys.DeriveMasterPriv("peer-meta")

	store, err := NewStore(fsys, master)
	require.NoError(t, err)

	require.NoError(t, store.SetFile(t.Context(), "a.txt", []byte("data")))
	initialCID := store.CurrentContentID()

	peerPub := []byte("peer-pub")
	peerCID := []byte("peer-cid")
	require.NoError(t, store.SetPeerContentID(peerPub, peerCID))

	// Content should remain unchanged.
	require.Equal(t, initialCID, store.CurrentContentID())

	// Metadata sidecar should exist.
	names, err := fsys.List()
	require.NoError(t, err)
	foundMeta := false
	for _, n := range names {
		if n == peersMetadataName {
			foundMeta = true
		}
	}
	require.True(t, foundMeta, "metadata sidecar not found")

	reloaded, err := NewStore(fsys, master)
	require.NoError(t, err)
	peers := reloaded.Peers()
	require.Len(t, peers, 1)
	require.Equal(t, peerPub, peers[0].GetOnionPubkey())
	require.Equal(t, peerCID, peers[0].GetContentId())

	// Removal updates metadata without touching content.
	require.NoError(t, reloaded.RemovePeerContent(peerPub))
	require.Equal(t, initialCID, reloaded.CurrentContentID())
	reloadedAgain, err := NewStore(fsys, master)
	require.NoError(t, err)
	require.Empty(t, reloadedAgain.Peers())
}

// TestPersistPeersMetadataAbort ensures temp files are discarded on write/finalize failure.
func TestPersistPeersMetadataAbort(t *testing.T) {
	t.Parallel()

	for name, cfg := range map[string]struct {
		failWrite    bool
		failFinalize bool
	}{
		"write-fails":    {failWrite: true},
		"finalize-fails": {failFinalize: true},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newAbortFS(cfg.failWrite, cfg.failFinalize)
			master := keys.DeriveMasterPriv("abort-meta")
			store, err := NewStore(fs, master)
			require.NoError(t, err)

			err = store.SetPeerContentID([]byte("peer"), []byte("cid"))
			require.Error(t, err)
			require.True(t, fs.aborted.Load(), "abort must be called")

			names, err := fs.List()
			require.NoError(t, err)
			require.Empty(t, names, "no files should remain after abort")
		})
	}
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
	xor, err := usercontent.NewAesCTR(fileKey)
	require.NoError(t, err)

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
	w, err := fsys.OpenWrite()
	require.NoError(t, err)
	_, err = w.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, w.Finalize(finalName))

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
	w, err := fsys.OpenWrite()
	require.NoError(t, err)
	_, err = w.Write(data[:len(data)-1])
	require.NoError(t, err)
	require.NoError(t, w.Finalize(name))
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
	xor, err := usercontent.NewAesCTR(fileKey)
	require.NoError(t, err)

	return &Store{
		fs:           fsys,
		files:        make(map[string]usercontent.File),
		contentSeal:  contentSeal,
		contentOpen:  contentOpen,
		metadataSeal: metadataSeal,
		metadataOpen: metadataOpen,
		xor:          xor,
	}
}

// firstContentFile returns the first content file found in the filesystem.
func firstContentFile(t *testing.T, fsys Filesystem) string {
	t.Helper()
	names, err := fsys.List()
	require.NoError(t, err)
	for _, name := range names {
		return name
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

type abortFS struct {
	base         *MapFilesystem
	aborted      atomic.Bool
	failWrite    bool
	failFinalize bool
}

func newAbortFS(failWrite, failFinalize bool) *abortFS {
	return &abortFS{
		base:         NewMapFilesystem(),
		failWrite:    failWrite,
		failFinalize: failFinalize,
	}
}

func (a *abortFS) OpenRead(name string) (ReadFile, error) {
	return a.base.OpenRead(name)
}

func (a *abortFS) OpenWrite() (WriteFile, error) {
	return &abortWrite{
		parent:       a,
		failWrite:    a.failWrite,
		failFinalize: a.failFinalize,
	}, nil
}

func (a *abortFS) Remove(name string) error {
	return a.base.Remove(name)
}

func (a *abortFS) List() ([]string, error) {
	return a.base.List()
}

type abortWrite struct {
	parent       *abortFS
	buf          bytes.Buffer
	failWrite    bool
	failFinalize bool
}

func (w *abortWrite) Write(p []byte) (int, error) {
	if w.failWrite {
		return 0, errors.New("forced write error")
	}
	return w.buf.Write(p)
}

func (w *abortWrite) Finalize(name string) error {
	if w.failFinalize {
		return errors.New("forced finalize error")
	}
	if name == "" {
		return nil
	}
	w.parent.base.mu.Lock()
	w.parent.base.files[name] = append([]byte(nil), w.buf.Bytes()...)
	w.parent.base.mu.Unlock()
	return nil
}

func (w *abortWrite) Abort() error {
	w.parent.aborted.Store(true)
	return nil
}

// OpenRead delegates to the underlying filesystem.
func (f *failingFS) OpenRead(name string) (ReadFile, error) {
	return f.delegate.OpenRead(name)
}

// OpenWrite wraps the writer to inject a single failure.
func (f *failingFS) OpenWrite() (WriteFile, error) {
	w, err := f.delegate.OpenWrite()
	if err != nil {
		return nil, err
	}
	return &failingWrite{
		w:       w,
		trigger: &f.failOnce,
	}, nil
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

// Finalize forwards to the underlying writer.
func (fw *failingWrite) Finalize(name string) error {
	return fw.w.Finalize(name)
}

func (fw *failingWrite) Abort() error {
	return fw.w.Abort()
}
