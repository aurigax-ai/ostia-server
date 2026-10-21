package main

import (
	"context"
	"errors"
	"flag"

	"filippo.io/age"

	"github.com/aurigax-ai/ostia-server/internal/server"
)

func backup(ctx context.Context, a *server.Admin, operands []string) error {
	sub := flag.NewFlagSet("backup", flag.ContinueOnError)
	recipient := sub.String("recipient", "", "age public key (age1...) allowed to decrypt the backup")
	out := sub.String("out", "", "path of the encrypted backup file to create")
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
	return a.Backup(ctx, key, *out)
}
