package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"filippo.io/age"

	"github.com/aurigax-ai/ostia-server/internal/server"
)

func backup(ctx context.Context, a *server.Admin, operands []string) error {
	sub := flag.NewFlagSet("backup", flag.ContinueOnError)
	recipient := sub.String("recipient", "", "age public key (age1...) allowed to decrypt the backup")
	out := sub.String("out", "", "path of the encrypted backup file to create, or - for standard output")
	if err := sub.Parse(operands); err != nil {
		return err
	}
	if *recipient == "" || *out == "" {
		return errors.New("backup needs -recipient and -out")
	}
	key, err := age.ParseX25519Recipient(*recipient)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *out == "-" {
		return backupToStdout(ctx, a, key)
	}
	return backupToFile(ctx, a, key, *out)
}

func backupToStdout(ctx context.Context, a *server.Admin, key age.Recipient) error {
	info, err := os.Stdout.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return errors.New("refusing to write the encrypted backup to a terminal; redirect standard output to a file")
	}
	return a.Backup(ctx, key, os.Stdout)
}

func backupToFile(ctx context.Context, a *server.Admin, key age.Recipient, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = errors.Join(a.Backup(ctx, key, f), f.Close())
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}
