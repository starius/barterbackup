package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/torserver"
)

// minimalServer embeds the unimplemented server to satisfy the interface.
type minimalServer struct {
	bbrpc.UnimplementedBarterBackupServerServer
}

func main() {
	// Derive master key material from password using a memory-hard function.
	// Read the password from BB_PASSWORD environment variable.
	pw := os.Getenv("BB_PASSWORD")
	if pw == "" {
		log.Fatalf("BB_PASSWORD env var must be set to the node password")
	}
	masterPriv := keys.DeriveMasterPriv(pw)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	srv, err := torserver.Start(ctx, torserver.Config{
		MasterPriv:      masterPriv,
		ListenOnionPort: 80,
	}, &minimalServer{})
	if err != nil {
		log.Fatalf("failed to start tor-backed gRPC server: %v", err)
	}
	defer srv.Close()

	log.Printf("bbrpc server is listening at %s.onion:%d", srv.OnionID(), 80)

	// Wait for termination signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("shutting down")
}
