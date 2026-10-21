package store

import (
	"context"
	"database/sql"
)

type PushHandle struct {
	Handle      string
	Platform    string
	TokenSealed []byte
	CreatedAt   int64
}

func (d *DB) AddPushHandle(ctx context.Context, h PushHandle, max int) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_handles`).Scan(&count); err != nil {
			return err
		}
		if max > 0 && count >= max {
			return ErrLimit
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO push_handles (handle, platform, token_sealed, created_at) VALUES (?, ?, ?, ?)`,
			h.Handle, h.Platform, h.TokenSealed, d.ms())
		return err
	})
}

func (d *DB) PushHandle(ctx context.Context, handle string) (PushHandle, error) {
	h := PushHandle{Handle: handle}
	err := d.sql.QueryRowContext(ctx, `SELECT platform, token_sealed, created_at FROM push_handles WHERE handle = ?`, handle).
		Scan(&h.Platform, &h.TokenSealed, &h.CreatedAt)
	return h, notFound(err)
}

func (d *DB) DeletePushHandle(ctx context.Context, handle string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM push_handles WHERE handle = ?`, handle)
	return affected(res, err)
}
