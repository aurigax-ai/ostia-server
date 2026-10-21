package store

import (
	"context"
	"database/sql"
	"time"
)

type PushHandle struct {
	Handle      string
	AccountID   string
	Platform    string
	TokenSealed []byte
	CreatedAt   int64
}

const maxOutstandingTickets = 10

func (d *DB) CreatePushTicket(ctx context.Context, hash []byte, accountID string, ttl time.Duration) (expiresAt int64, err error) {
	expiresAt = d.now().Add(ttl).UnixMilli()
	err = d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM push_tickets WHERE expires_at <= ?`, d.ms()); err != nil {
			return err
		}
		var open int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_tickets WHERE account_id = ?`, accountID).Scan(&open); err != nil {
			return err
		}
		if open >= maxOutstandingTickets {
			return ErrLimit
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO push_tickets (hash, account_id, expires_at) VALUES (?, ?, ?)`, hash, accountID, expiresAt)
		return err
	})
	return expiresAt, err
}

func (d *DB) RegisterPushHandle(ctx context.Context, ticketHash []byte, h PushHandle, maxPerAccount, maxTotal int) (PushHandle, error) {
	err := d.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `DELETE FROM push_tickets WHERE hash = ? AND expires_at > ? RETURNING account_id`, ticketHash, d.ms()).Scan(&h.AccountID)
		if err != nil {
			return notFound(err)
		}
		var mine, total int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE account_id = ?), COUNT(*) FROM push_handles`, h.AccountID).Scan(&mine, &total); err != nil {
			return err
		}
		if maxTotal > 0 && total >= maxTotal {
			return ErrLimit
		}
		for maxPerAccount > 0 && mine >= maxPerAccount {
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM push_handles WHERE handle = (SELECT handle FROM push_handles WHERE account_id = ? ORDER BY created_at, rowid LIMIT 1)`, h.AccountID); err != nil {
				return err
			}
			mine--
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO push_handles (handle, account_id, platform, token_sealed, created_at) VALUES (?, ?, ?, ?, ?)`,
			h.Handle, h.AccountID, h.Platform, h.TokenSealed, d.ms())
		return err
	})
	return h, err
}

func (d *DB) PushHandle(ctx context.Context, handle string) (PushHandle, error) {
	h := PushHandle{Handle: handle}
	err := d.sql.QueryRowContext(ctx, `SELECT account_id, platform, token_sealed, created_at FROM push_handles WHERE handle = ?`, handle).
		Scan(&h.AccountID, &h.Platform, &h.TokenSealed, &h.CreatedAt)
	return h, notFound(err)
}

func (d *DB) DeletePushHandle(ctx context.Context, handle string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM push_handles WHERE handle = ?`, handle)
	return affected(res, err)
}

func (d *DB) SweepPushTickets(ctx context.Context) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM push_tickets WHERE expires_at <= ?`, d.ms())
	return err
}
