package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const scratchPrefix = ".backup-scratch-"

func removeScratch(dataDir string) {
	entries, _ := os.ReadDir(dataDir)
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), scratchPrefix) {
			_ = os.RemoveAll(filepath.Join(dataDir, entry.Name()))
		}
	}
}

func (a *Admin) Backup(ctx context.Context, recipient age.Recipient, out io.Writer) error {
	scratch, err := os.MkdirTemp(a.Cfg.DataDir, scratchPrefix)
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	plain := filepath.Join(scratch, "ostia.sqlite")
	if err := a.DB.VacuumInto(ctx, plain); err != nil {
		return err
	}
	src, err := os.Open(plain)
	if err != nil {
		return err
	}
	defer src.Close()
	enc, err := age.Encrypt(out, recipient)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(enc, &ctxReader{ctx: ctx, r: src})
	return errors.Join(copyErr, enc.Close())
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
