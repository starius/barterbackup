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

// WaitForState waits until local cli keys exist and the node answers State.
func (n *Node) WaitForState(ctx context.Context) (*clirpc.StateResponse, error) {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		if !n.hasCLIKeys() {
			time.Sleep(200 * time.Millisecond)
			continue
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

// Init initializes the node's storage with its configured password.
func (n *Node) Init(ctx context.Context) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.Init(ctx, &clirpc.InitRequest{MainPassword: n.password})
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

// SetFile uploads one plaintext file into the daemon.
func (n *Node) SetFile(ctx context.Context, name string, data []byte) error {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = client.SetFile(ctx, &clirpc.SetFileRequest{
		File: &clirpc.File{Name: name, Data: data},
	})
	if err != nil {
		return fmt.Errorf("set file %s on %s: %w", name, n.name, err)
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
	response, err := client.GetFile(ctx, &clirpc.GetFileRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("get file %s from %s: %w", name, n.name, err)
	}
	return response.File, nil
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

// ProposeContractUntilSuccess retries one contract proposal until it succeeds or times out.
func (n *Node) ProposeContractUntilSuccess(ctx context.Context, peerOnion string) (*clirpc.ProposeContractUpdate, error) {
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

// RecoverContentUntilRecovered retries recovery until one update reports success.
func (n *Node) RecoverContentUntilRecovered(ctx context.Context) (*clirpc.RecoverContentUpdate, error) {
	deadline, cancel := context.WithTimeout(ctx, defaultLongTimeout)
	defer cancel()

	for {
		update, err := n.recoverContentOnce(deadline)
		if err == nil && update.RecoveredMostRecentVersion {
			return update, nil
		}
		if err := ctxErr(deadline); err != nil {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
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

func (n *Node) proposeContractOnce(ctx context.Context, peerOnion string) (*clirpc.ProposeContractUpdate, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := client.ProposeContract(ctx, &clirpc.ProposeContractRequest{
		Peer: &clirpc.Peer{OnionServiceId: peerOnion},
	})
	if err != nil {
		return nil, fmt.Errorf("propose contract from %s to %s: %w", n.name, peerOnion, err)
	}

	var last *clirpc.ProposeContractUpdate
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

func (n *Node) recoverContentOnce(ctx context.Context) (*clirpc.RecoverContentUpdate, error) {
	client, conn, err := DialLocalClient(ctx, n.localAddr, n.keysDir())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := client.RecoverContent(ctx, &clirpc.RecoverContentRequest{})
	if err != nil {
		return nil, fmt.Errorf("recover content on %s: %w", n.name, err)
	}
	var last *clirpc.RecoverContentUpdate
	for {
		update, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, fmt.Errorf("receive recovery update from %s: %w", n.name, recvErr)
		}
		last = update
	}
	if last == nil {
		return nil, fmt.Errorf("recovery stream on %s returned no updates", n.name)
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
