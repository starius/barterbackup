package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/starius/barterbackup/cmd/bbcli/bbcliapp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := bbcliapp.Run(ctx, bbcliapp.WithOSArgs()); err != nil {
		// go-flags already prints errors/help; avoid duplicate output.
		os.Exit(2)
	}
}
