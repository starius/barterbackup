package bbnode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/netmock"
	"github.com/stretchr/testify/require"
)

func TestLocalStoragePersistenceAndEncryption(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := netmock.NewMockNetwork()
	dir := t.TempDir()

	n, err := New("pw", mock, dir)
	require.NoError(t, err)
	require.NoError(t, n.Start(ctx))

	_, err = n.SetFile(ctx, &clirpc.SetFileRequest{File: &clirpc.File{Name: "note.txt", Data: []byte("hello world")}})
	require.NoError(t, err)

	list, err := n.ListFiles(ctx, &clirpc.ListFilesRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"note.txt"}, list.GetName())

	resp, err := n.GetFile(ctx, &clirpc.GetFileRequest{Name: "note.txt"})
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), resp.GetFile().GetData())

	blob, err := os.ReadFile(filepath.Join(dir, "content.bin"))
	require.NoError(t, err)
	require.NotContains(t, string(blob), "hello world")

	require.NoError(t, n.Stop())

	nReload, err := New("pw", mock, dir)
	require.NoError(t, err)
	require.NoError(t, nReload.Start(ctx))
	defer func() { _ = nReload.Stop() }()

	respReload, err := nReload.GetFile(ctx, &clirpc.GetFileRequest{Name: "note.txt"})
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), respReload.GetFile().GetData())
}

func TestLocalStorageWrongPasswordFails(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock := netmock.NewMockNetwork()
	dir := t.TempDir()

	n, err := New("pw", mock, dir)
	require.NoError(t, err)
	require.NoError(t, n.Start(ctx))

	_, err = n.SetFile(ctx, &clirpc.SetFileRequest{File: &clirpc.File{Name: "note.txt", Data: []byte("secret")}})
	require.NoError(t, err)
	require.NoError(t, n.Stop())

	_, err = New("wrong", mock, dir)
	require.Error(t, err)
}
