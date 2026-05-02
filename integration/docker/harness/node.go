package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"barterbackup/integration/docker/gen/clirpc"
)

const localFileChunkBytes = 256 * 1024

// WaitForState waits until local cli keys exist and the node answers State.
func (n *Node) WaitForState(ctx context.Context) (*clirpc.StateResponse, error) {
	if err := n.WaitForLocalRPC(ctx); err != nil {
		return nil, err
	}
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		client, conn, err := DialLocalClient(deadline, n.localAddr, n.keysDir())
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		response, rpcErr := client.State(deadline, &clirpc.StateRequest{})
		_ = conn.Close()
		if rpcErr == nil {
			return response, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// WaitForLocalRPC waits until local cli keys exist and the node accepts one
// local mTLS connection.
func (n *Node) WaitForLocalRPC(ctx context.Context) error {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		if err := ctxErr(deadline); err != nil {
			return err
		}
		if !n.hasCLIKeys() {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		_, conn, err := DialLocalClient(deadline, n.localAddr, n.keysDir())
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// State returns one direct State RPC response from the local daemon.
func (n *Node) State(ctx context.Context) (*clirpc.StateResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.State(ctx, &clirpc.StateRequest{})
	if err != nil {
		return nil, fmt.Errorf("get state from %s: %w", n.name, err)
	}
	return response, nil
}

// Init initializes the node's storage with its configured password.
func (n *Node) Init(ctx context.Context) error {
	return n.InitWithRecoveryMode(ctx, false)
}

// InitWithRecoveryMode initializes the node and optionally keeps publication
// disabled until recovery is finished.
func (n *Node) InitWithRecoveryMode(ctx context.Context, recoveryMode bool) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.Init(ctx, &clirpc.InitRequest{
		MainPassword: n.password,
		RecoveryMode: recoveryMode,
	})
	if err != nil {
		return fmt.Errorf("init %s: %w", n.name, err)
	}
	return nil
}

// Unlock unlocks the node's encrypted storage with its configured password.
func (n *Node) Unlock(ctx context.Context) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.Unlock(ctx, &clirpc.UnlockRequest{MainPassword: n.password})
	if err != nil {
		return fmt.Errorf("unlock %s: %w", n.name, err)
	}
	return nil
}

// WaitForReady waits until the node reports a ready peer runtime.
func (n *Node) WaitForReady(ctx context.Context) (*clirpc.StateResponse, error) {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		state, err := n.WaitForState(deadline)
		if err != nil {
			return nil, err
		}
		if state.PeerRuntimeState == clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_READY {
			return state, nil
		}
		if state.PeerRuntimeState == clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_FAILED {
			return nil, fmt.Errorf("peer runtime failed for %s: %s", n.name, state.PeerRuntimeError)
		}
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// GetTestTime returns the daemon's hidden logical test time.
func (n *Node) GetTestTime(ctx context.Context) (*clirpc.GetTestTimeResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.GetTestTime(ctx, &clirpc.GetTestTimeRequest{})
	if err != nil {
		return nil, fmt.Errorf("get test time on %s: %w", n.name, err)
	}
	return response, nil
}

// SetTestTime sets the daemon's hidden logical test time exactly.
func (n *Node) SetTestTime(
	ctx context.Context,
	seconds uint64,
	nanoseconds uint32,
) (*clirpc.SetTestTimeResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.SetTestTime(ctx, &clirpc.SetTestTimeRequest{
		UnixSeconds: seconds,
		Nanoseconds: nanoseconds,
	})
	if err != nil {
		return nil, fmt.Errorf("set test time on %s: %w", n.name, err)
	}
	return response, nil
}

// AdvanceTestTime advances the daemon's hidden logical test time.
func (n *Node) AdvanceTestTime(
	ctx context.Context,
	seconds uint64,
	nanoseconds uint32,
) (*clirpc.AdvanceTestTimeResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.AdvanceTestTime(ctx, &clirpc.AdvanceTestTimeRequest{
		Seconds:     seconds,
		Nanoseconds: nanoseconds,
	})
	if err != nil {
		return nil, fmt.Errorf("advance test time on %s: %w", n.name, err)
	}
	return response, nil
}

// TimerIntercept opens one hidden timer-intercept stream for the given label.
func (n *Node) TimerIntercept(ctx context.Context, label string) (*TimerInterceptStream, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithCancel(context.Background())
	stream, err := client.TimerIntercept(streamCtx, &clirpc.TimerInterceptRequest{Label: label})
	if err != nil {
		cancel()
		_ = conn.Close()
		return nil, fmt.Errorf("timer intercept %s on %s: %w", label, n.name, err)
	}
	return &TimerInterceptStream{conn: conn, stream: stream, cancel: cancel}, nil
}

// WaitForPeerStorage waits until the peer inventory reports mirrored content.
func (n *Node) WaitForPeerStorage(
	ctx context.Context,
	peerOnion string,
	expectedBytes int64,
) (*clirpc.PeerInfo, error) {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		peers, err := n.Peers(deadline)
		if err == nil {
			for _, peer := range peers.Peers {
				if peer.GetPeer().GetOnionServiceId() != peerOnion {
					continue
				}
				if peer.StoredContentBytes >= expectedBytes && peer.LatestCachedContentLength >= expectedBytes {
					return peer, nil
				}
			}
		}
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ConnectPeer registers one peer onion in the local daemon.
func (n *Node) ConnectPeer(ctx context.Context, onion string) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.ConnectPeer(ctx, &clirpc.ConnectPeerRequest{
		Peer: &clirpc.Peer{OnionServiceId: onion},
	})
	if err != nil {
		return fmt.Errorf("connect peer %s from %s: %w", onion, n.name, err)
	}
	return nil
}

// PinPeer marks one tracked peer as operator-pinned on the daemon.
func (n *Node) PinPeer(ctx context.Context, onion string) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.PinPeer(ctx, &clirpc.PinPeerRequest{
		Peer: &clirpc.Peer{OnionServiceId: onion},
	})
	if err != nil {
		return fmt.Errorf("pin peer %s from %s: %w", onion, n.name, err)
	}
	return nil
}

// UnpinPeer removes one operator pin from a tracked peer on the daemon.
func (n *Node) UnpinPeer(ctx context.Context, onion string) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.UnpinPeer(ctx, &clirpc.UnpinPeerRequest{
		Peer: &clirpc.Peer{OnionServiceId: onion},
	})
	if err != nil {
		return fmt.Errorf("unpin peer %s from %s: %w", onion, n.name, err)
	}
	return nil
}

// SetFile uploads one plaintext file into the daemon.
func (n *Node) SetFile(ctx context.Context, name string, data []byte) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	stream, err := client.SetFileStream(ctx)
	if err != nil {
		return fmt.Errorf("open streamed set file %s on %s: %w", name, n.name, err)
	}
	if err := stream.Send(&clirpc.SetFileChunk{
		Chunk: &clirpc.SetFileChunk_File{
			File: &clirpc.FileInfo{
				Name:       name,
				SizeBytes:  int64(len(data)),
				ModifiedAt: 0,
			},
		},
	}); err != nil {
		return fmt.Errorf("send file metadata for %s on %s: %w", name, n.name, err)
	}
	for len(data) > 0 {
		chunkLen := len(data)
		if chunkLen > localFileChunkBytes {
			chunkLen = localFileChunkBytes
		}
		if err := stream.Send(&clirpc.SetFileChunk{
			Chunk: &clirpc.SetFileChunk_Data{
				Data: data[:chunkLen],
			},
		}); err != nil {
			return fmt.Errorf("send file chunk for %s on %s: %w", name, n.name, err)
		}
		data = data[chunkLen:]
	}
	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("set file %s on %s: %w", name, n.name, err)
	}
	return nil
}

// DeleteFile removes one plaintext file from the daemon's current content set.
func (n *Node) DeleteFile(ctx context.Context, name string) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.DeleteFile(ctx, &clirpc.DeleteFileRequest{Name: name})
	if err != nil {
		return fmt.Errorf("delete file %s on %s: %w", name, n.name, err)
	}
	return nil
}

// ListFiles returns the current file list from the daemon.
func (n *Node) ListFiles(ctx context.Context) (*clirpc.ListFilesResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.ListFiles(ctx, &clirpc.ListFilesRequest{})
	if err != nil {
		return nil, fmt.Errorf("list files on %s: %w", n.name, err)
	}
	return response, nil
}

// GetFile downloads one plaintext file from the daemon.
func (n *Node) GetFile(ctx context.Context, name string) (*clirpc.File, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stream, err := client.GetFileStream(ctx, &clirpc.GetFileRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("get file %s from %s: %w", name, n.name, err)
	}
	var file *clirpc.File
	for {
		chunk, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, fmt.Errorf("receive file %s from %s: %w", name, n.name, recvErr)
		}
		switch typed := chunk.GetChunk().(type) {
		case *clirpc.GetFileChunk_File:
			if file != nil {
				return nil, fmt.Errorf("get file %s from %s started a second file", name, n.name)
			}
			file = &clirpc.File{
				Name:         typed.File.GetName(),
				ModifiedAt:   typed.File.GetModifiedAt(),
				ModifiedAtNs: typed.File.GetModifiedAtNs(),
			}
		case *clirpc.GetFileChunk_Data:
			if file == nil {
				return nil, fmt.Errorf("get file %s from %s sent data before metadata", name, n.name)
			}
			file.Data = append(file.Data, typed.Data...)
		default:
			return nil, fmt.Errorf("get file %s from %s returned an empty chunk", name, n.name)
		}
	}
	if file == nil {
		return nil, fmt.Errorf("get file %s from %s returned no file", name, n.name)
	}
	return file, nil
}

// ExportBuiltInPeers renders the full Rust source for the built-in peer list.
func (n *Node) ExportBuiltInPeers(ctx context.Context) (*clirpc.ExportBuiltInPeersResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.ExportBuiltInPeers(ctx, &clirpc.ExportBuiltInPeersRequest{})
	if err != nil {
		return nil, fmt.Errorf("export built-in peers from %s: %w", n.name, err)
	}
	return response, nil
}

// Peers returns the current peer inventory without live probing.
func (n *Node) Peers(ctx context.Context) (*clirpc.PeersResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.Peers(ctx, &clirpc.PeersRequest{})
	if err != nil {
		return nil, fmt.Errorf("get peers from %s: %w", n.name, err)
	}
	return response, nil
}

// SetStorageConfig updates the local peer-storage policy.
func (n *Node) SetStorageConfig(
	ctx context.Context,
	config *clirpc.StorageConfig,
) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.SetStorageConfig(ctx, &clirpc.SetStorageConfigRequest{Config: config})
	if err != nil {
		return fmt.Errorf("set storage config on %s: %w", n.name, err)
	}
	return nil
}

// GetStorageConfig returns the current storage policy and derived usage info.
func (n *Node) GetStorageConfig(ctx context.Context) (*clirpc.GetStorageConfigResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.GetStorageConfig(ctx, &clirpc.GetStorageConfigRequest{})
	if err != nil {
		return nil, fmt.Errorf("get storage config from %s: %w", n.name, err)
	}
	return response, nil
}

// GetPeerStorage returns the current live peer-storage snapshot.
func (n *Node) GetPeerStorage(ctx context.Context) (*clirpc.GetPeerStorageResponse, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := client.GetPeerStorage(ctx, &clirpc.GetPeerStorageRequest{})
	if err != nil {
		return nil, fmt.Errorf("get contracts from %s: %w", n.name, err)
	}
	return response, nil
}

// PublishToPeer runs one peer publication and returns the last update.
func (n *Node) PublishToPeer(
	ctx context.Context,
	peerOnion string,
) (*clirpc.PublishToPeerUpdate, error) {
	return n.proposeContractOnce(ctx, peerOnion)
}

// PublishToPeerUntilSuccess retries one peer publication until it succeeds or times out.
func (n *Node) PublishToPeerUntilSuccess(ctx context.Context, peerOnion string) (*clirpc.PublishToPeerUpdate, error) {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		update, err := n.proposeContractOnce(deadline, peerOnion)
		if err == nil {
			return update, nil
		}
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// VerifyPeerStorage runs one peer verification and returns the last update.
func (n *Node) VerifyPeerStorage(
	ctx context.Context,
	peerOnion string,
) (*clirpc.VerifyPeerStorageUpdate, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := client.VerifyPeerStorage(ctx, &clirpc.VerifyPeerStorageRequest{
		Peer: &clirpc.Peer{OnionServiceId: peerOnion},
	})
	if err != nil {
		return nil, fmt.Errorf("check contract from %s to %s: %w", n.name, peerOnion, err)
	}

	var last *clirpc.VerifyPeerStorageUpdate
	for {
		update, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, fmt.Errorf("receive check update from %s: %w", n.name, recvErr)
		}
		last = update
	}
	if last == nil {
		return nil, fmt.Errorf("peer verification from %s to %s returned no updates", n.name, peerOnion)
	}
	return last, nil
}

// VerifyPeerStorageUntilSuccess retries one peer verification until it succeeds or times out.
func (n *Node) VerifyPeerStorageUntilSuccess(ctx context.Context, peerOnion string) (*clirpc.VerifyPeerStorageUpdate, error) {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		update, err := n.checkContractOnce(deadline, peerOnion)
		if err == nil {
			return update, nil
		}
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// InitComplete disables recovery mode and advances the recovery watermark to
// the current generation boundary.
func (n *Node) InitComplete(ctx context.Context) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.InitComplete(ctx, &clirpc.InitCompleteRequest{})
	if err != nil {
		return fmt.Errorf("complete initialization on %s: %w", n.name, err)
	}
	return nil
}

// Stop asks the daemon to stop gracefully and waits for the container to exit.
func (n *Node) Stop(ctx context.Context) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	_, stopErr := client.Stop(ctx, &clirpc.StopRequest{})
	_ = conn.Close()
	if stopErr != nil {
		return fmt.Errorf("stop %s: %w", n.name, stopErr)
	}

	deadline, cancel := context.WithTimeout(ctx, defaultShortTimeout)
	defer cancel()
	for {
		output, err := runCommand(deadline, n.suite.repoRoot, nil, "docker", "inspect", "-f", "{{.State.Running}}", n.containerName)
		if err != nil {
			return nil
		}
		if string(bytesTrimSpace(output)) == "false" {
			return nil
		}
		if err := ctxErr(deadline); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (n *Node) proposeContractOnce(ctx context.Context, peerOnion string) (*clirpc.PublishToPeerUpdate, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := client.PublishToPeer(ctx, &clirpc.PublishToPeerRequest{
		Peer: &clirpc.Peer{OnionServiceId: peerOnion},
	})
	if err != nil {
		return nil, fmt.Errorf("propose contract from %s to %s: %w", n.name, peerOnion, err)
	}

	var last *clirpc.PublishToPeerUpdate
	for {
		update, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, fmt.Errorf("receive proposal update from %s: %w", n.name, recvErr)
		}
		last = update
	}
	if last == nil || !last.Success {
		return nil, fmt.Errorf("proposal from %s to %s did not finish successfully", n.name, peerOnion)
	}
	return last, nil
}

func (n *Node) checkContractOnce(ctx context.Context, peerOnion string) (*clirpc.VerifyPeerStorageUpdate, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := client.VerifyPeerStorage(ctx, &clirpc.VerifyPeerStorageRequest{
		Peer: &clirpc.Peer{OnionServiceId: peerOnion},
	})
	if err != nil {
		return nil, fmt.Errorf("check contract from %s to %s: %w", n.name, peerOnion, err)
	}

	var last *clirpc.VerifyPeerStorageUpdate
	for {
		update, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, fmt.Errorf("receive check update from %s: %w", n.name, recvErr)
		}
		last = update
	}
	if last == nil || !last.Success {
		return nil, fmt.Errorf("peer verification from %s to %s did not finish successfully", n.name, peerOnion)
	}
	return last, nil
}

func (n *Node) hasCLIKeys() bool {
	serverPath := filepath.Join(n.keysDir(), "server.pub")
	clientPath := filepath.Join(n.keysDir(), "client.key")
	if _, err := os.Stat(serverPath); err != nil {
		return false
	}
	if _, err := os.Stat(clientPath); err != nil {
		return false
	}
	return true
}

func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func bytesTrimSpace(input []byte) []byte {
	for len(input) > 0 && (input[0] == ' ' || input[0] == '\n' || input[0] == '\t' || input[0] == '\r') {
		input = input[1:]
	}
	for len(input) > 0 {
		last := input[len(input)-1]
		if last != ' ' && last != '\n' && last != '\t' && last != '\r' {
			break
		}
		input = input[:len(input)-1]
	}
	return input
}
