package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

func main() {
	address := flag.String("address", "", "Valkey address")
	prefix := flag.String("key-prefix", valkey.DefaultKeyPrefix, "OAuth storage key prefix")
	database := flag.Int("db", 0, "Valkey database")
	passwordFile := flag.String("password-file", "", "File containing the Valkey password")
	useTLS := flag.Bool("tls", false, "Use TLS with system certificate verification")
	writersStopped := flag.Bool("writers-stopped", false, "Confirm all OAuth traffic and writers older than v1.17.2 are stopped")
	timeout := flag.Duration("timeout", 10*time.Minute, "Migration deadline")
	flag.Parse()
	if !*writersStopped || *address == "" {
		fmt.Fprintln(os.Stderr, "Stop all OAuth traffic and old writers, then provide -writers-stopped and -address")
		os.Exit(1)
	}
	configuration := valkey.Config{Address: *address, KeyPrefix: *prefix, DB: *database}
	if *passwordFile != "" {
		password, err := os.ReadFile(*passwordFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot read Valkey password file")
			os.Exit(1)
		}
		configuration.Password = strings.TrimRight(string(password), "\r\n")
	}
	if *useTLS {
		configuration.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if err := migrate(configuration, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "Migration failed; keep traffic stopped: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Migration complete; restart OAuth servers with the new release before restoring traffic")
}

func migrate(configuration valkey.Config, timeout time.Duration) error {
	store, err := valkey.New(configuration)
	if err != nil {
		return err
	}
	defer store.Close()
	shutdown, cancelShutdown := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelShutdown()
	ctx, cancel := context.WithTimeout(shutdown, timeout)
	defer cancel()
	return store.MigrateFamilyRevocations(ctx)
}
