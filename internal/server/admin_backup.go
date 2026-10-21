package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

const scratchPattern = "backup-*"

func removeScratch(dataDir string) {
	stale, _ := filepath.Glob(filepath.Join(dataDir, scratchPattern))
	for _, dir := range stale {
		_ = os.RemoveAll(dir)
	}
}

func (a *Admin) Backup(ctx context.Context, recipient age.Recipient, out io.Writer) error {
	scratch, err := os.MkdirTemp(a.Cfg.DataDir, "backup-")
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
