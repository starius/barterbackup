package fswrap

import (
	"bytes"
	"testing"

	"crypto/sha256"
	"github.com/starius/barterbackup/internal/bbnode/userstorage"
	"github.com/stretchr/testify/require"
)

// TestWrapperRoundTrip verifies filenames and contents are wrapped and unwrapped.
func TestWrapperRoundTrip(t *testing.T) {
	t.Parallel()

	base := userstorage.NewMapFilesystem()
	w, err := New(base, bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)

	name := "secret.txt"
	plain := []byte("hello world")

	writer, err := w.OpenWrite(name)
	require.NoError(t, err)
	_, err = writer.Write(plain)
	require.NoError(t, err)
	require.NoError(t, writer.Sync())
	require.NoError(t, writer.Close())

	names, err := base.List()
	require.NoError(t, err)
	require.Len(t, names, 1)
	require.NotEqual(t, name, names[0], "filename must be wrapped")

	reader, err := w.OpenRead(name)
	require.NoError(t, err)
	defer reader.Close()
	buf := make([]byte, len(plain))
	n, err := reader.ReadAt(buf, 0)
	require.NoError(t, err)
	require.Equal(t, len(plain), n)
	require.Equal(t, plain, buf)
}

// TestWrapperSkipsUndecodableName ensures undecodable names are ignored by List.
func TestWrapperSkipsUndecodableName(t *testing.T) {
	t.Parallel()

	base := userstorage.NewMapFilesystem()
	w, err := New(base, bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)

	// Inject an undecodable filename.
	wr, err := base.OpenWrite("%%%")
	require.NoError(t, err)
	require.NoError(t, wr.Close())

	names, err := w.List()
	require.NoError(t, err)
	require.Empty(t, names)
}

// TestWrapperContentCorruption reports altered plaintext on tampered ciphertext.
func TestWrapperContentCorruption(t *testing.T) {
	t.Parallel()

	base := userstorage.NewMapFilesystem()
	w, err := New(base, bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)

	name := "file.bin"
	data := []byte("AAAAAA")

	writer, err := w.OpenWrite(name)
	require.NoError(t, err)
	_, err = writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Sync())
	require.NoError(t, writer.Close())

	// Tamper ciphertext: flip a byte in the underlying file.
	rawName := baseOnlyName(t, base)
	r, err := base.OpenRead(rawName)
	require.NoError(t, err)
	raw := make([]byte, r.Size())
	_, err = r.ReadAt(raw, 0)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	raw[0] ^= 0xff
	wr, err := base.OpenWrite(rawName)
	require.NoError(t, err)
	_, err = wr.Write(raw)
	require.NoError(t, err)
	require.NoError(t, wr.Sync())
	require.NoError(t, wr.Close())

	reader, err := w.OpenRead(name)
	require.NoError(t, err)
	defer reader.Close()
	buf := make([]byte, len(data))
	_, err = reader.ReadAt(buf, 0)
	require.NoError(t, err)
	require.NotEqual(t, data, buf, "corruption should alter plaintext")
}

// TestWrapperHashCachesAndInvalidates ensures hashes are cached and invalidated on write/remove/rename.
func TestWrapperHashCachesAndInvalidates(t *testing.T) {
	t.Parallel()

	base := userstorage.NewMapFilesystem()
	w, err := New(base, bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)

	name := "file.bin"
	data := []byte("payload")
	sum := sha256.Sum256(data)

	write := func(content []byte) {
		writer, err := w.OpenWrite(name)
		require.NoError(t, err)
		_, err = writer.Write(content)
		require.NoError(t, err)
		require.NoError(t, writer.Sync())
		require.NoError(t, writer.Close())
	}

	write(data)

	h, err := w.Hash(name)
	require.NoError(t, err)
	require.Equal(t, sum[:], h)

	// Cached value should be returned until invalidated.
	h2, err := w.Hash(name)
	require.NoError(t, err)
	require.Equal(t, h, h2)

	// Rewrite invalidates cache.
	newData := []byte("different")
	write(newData)
	h3, err := w.Hash(name)
	require.NoError(t, err)
	require.NotEqual(t, h, h3)
	sumNew := sha256.Sum256(newData)
	require.Equal(t, sumNew[:], h3)

	// Rename preserves cache under new name and clears old name.
	newName := "renamed.bin"
	require.NoError(t, w.Rename(name, newName))
	h4, err := w.Hash(newName)
	require.NoError(t, err)
	require.Equal(t, h3, h4)
	_, err = w.Hash(name)
	require.Error(t, err)

	// Remove clears cache.
	require.NoError(t, w.Remove(newName))
	_, err = w.Hash(newName)
	require.Error(t, err)
}

// baseOnlyName extracts the single filename from the underlying map fs.
func baseOnlyName(t *testing.T, fs userstorage.Filesystem) string {
	t.Helper()
	names, err := fs.List()
	require.NoError(t, err)
	if len(names) != 1 {
		t.Fatalf("expected 1 file, got %d", len(names))
	}
	return names[0]
}

// TestWrapperInvalidKeyLength ensures short master fails.
func TestWrapperInvalidKeyLength(t *testing.T) {
	t.Parallel()
	base := userstorage.NewMapFilesystem()
	_, err := New(base, []byte("short"))
	require.Error(t, err)
}
