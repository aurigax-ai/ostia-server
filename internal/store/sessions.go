package store

import (
	"context"
	"time"
)

func (d *DB) CreateSession(ctx context.Context, tokenHash []byte, deviceID string, ttl time.Duration) (expiresAt int64, err error) {
	expiresAt = d.now().Add(ttl).UnixMilli()
	_, err = d.sql.ExecContext(ctx, `INSERT INTO sessions (token_hash, device_id, expires_at) VALUES (?, ?, ?)`, tokenHash, deviceID, expiresAt)
	return expiresAt, err
}

func (d *DB) SessionDevice(ctx context.Context, tokenHash []byte) (Device, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT d.id, d.account_id, d.name, d.sign_pub, d.box_pub, d.created_at, d.last_seen_at, d.revoked_at
		FROM sessions s JOIN devices d ON d.id = s.device_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND d.revoked_at = 0`, tokenHash, d.ms())
	return scanDevice(row)
}

func (d *DB) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (d *DB) SweepSessions(ctx context.Context) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, d.ms())
	return err
}

func (d *DB) CountRows(ctx context.Context, sessions, invites *int) error {
	if err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(sessions); err != nil {
		return err
	}
	return d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites`).Scan(invites)
}
