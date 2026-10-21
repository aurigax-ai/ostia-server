package store

import (
	"context"
	"database/sql"
)

type Wrap struct {
	Slot      string
	Blob      []byte
	UpdatedAt int64
}

func (d *DB) PutWrap(ctx context.Context, accountID, slot string, blob []byte) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO key_wraps (account_id, slot, blob, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (account_id, slot) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at`,
		accountID, slot, blob, d.ms())
	return err
}

func (d *DB) Wrap(ctx context.Context, accountID, slot string) (Wrap, error) {
	w := Wrap{Slot: slot}
	err := d.sql.QueryRowContext(ctx, `SELECT blob, updated_at FROM key_wraps WHERE account_id = ? AND slot = ?`, accountID, slot).Scan(&w.Blob, &w.UpdatedAt)
	return w, notFound(err)
}

func (d *DB) Wraps(ctx context.Context, accountID string) ([]Wrap, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT slot, updated_at FROM key_wraps WHERE account_id = ? ORDER BY slot`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Wrap
	for rows.Next() {
		var w Wrap
		if err := rows.Scan(&w.Slot, &w.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (d *DB) DeleteWrap(ctx context.Context, accountID, slot string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM key_wraps WHERE account_id = ? AND slot = ?`, accountID, slot)
	return affected(res, err)
}

func putWrapTx(ctx context.Context, tx *sql.Tx, now int64, accountID, slot string, blob []byte) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO key_wraps (account_id, slot, blob, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (account_id, slot) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at`,
		accountID, slot, blob, now)
	return err
}
