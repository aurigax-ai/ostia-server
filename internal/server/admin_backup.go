package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

func (a *Admin) Backup(ctx context.Context, recipient age.Recipient, out string) (err error) {
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
	dst, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(out)
		}
	}()
	enc, err := age.Encrypt(dst, recipient)
	if err != nil {
		_ = dst.Close()
		return err
	}
	_, copyErr := io.Copy(enc, src)
	return errors.Join(copyErr, enc.Close(), dst.Close())
}
