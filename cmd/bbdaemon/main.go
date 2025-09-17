package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/starius/barterbackup/internal/nettor"
	"github.com/starius/barterbackup/internal/node"
)

func main() {
	// Read the password from BB_PASSWORD environment variable.
	pw := os.Getenv("BB_PASSWORD")
	if pw == "" {
		log.Fatalf("BB_PASSWORD env var must be set to the node password")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	n, err := node.New(pw, nettor.NewTorNetwork())
	if err != nil {
		log.Fatalf("failed to create node: %v", err)
	}
	if err := n.Start(ctx); err != nil {
		log.Fatalf("failed to start node: %v", err)
	}
	defer n.Stop()

	log.Printf("node is listening at %s", n.Address())

	// Wait for termination signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("shutting down")
}
