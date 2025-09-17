package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/starius/barterbackup/cmd/bbd/bbdapp"
)

func main() {
	cfg, err := bbdapp.Parse(bbdapp.WithOSArgs())
	if err != nil {
		log.Fatalf("parse flags: %v", err)
	}
	if cfg == nil { // help printed
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := bbdapp.Run(ctx, *cfg); err != nil {
		log.Fatalf("daemon start error: %v", err)
	}
	log.Println("bbd stopped")
}
