package bbcliapp

import (
	"context"
	"fmt"
	"time"

	"github.com/starius/barterbackup/clirpc"
)

// HealthcheckCmd runs the healthcheck subcommand.
type HealthcheckCmd struct{ cfg *Config }

func (c *HealthcheckCmd) Execute(args []string) error {
	cli := c.cfg.runtime.client
	hctx, cancel := context.WithTimeout(c.cfg.runtime.ctx, 5*time.Second)
	defer cancel()
	resp, err := cli.LocalHealthCheck(hctx, &clirpc.HealthCheckRequest{})
	if err != nil {
		return err
	}
	fmt.Printf("Server onion: %s\n", resp.GetServerOnion())
	up := time.Duration(resp.GetUptimeSeconds()) * time.Second
	fmt.Printf("Uptime: %s\n", up)
	return nil
}
