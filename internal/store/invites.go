package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (d *DB) CreateInvite(ctx context.Context, codeHash []byte, accountID string, ttl time.Duration, hint string) (expiresAt int64, err error) {
	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}
	expiresAt = d.now().Add(ttl).UnixMilli()
	var account any
	if accountID != "" {
		account = accountID
	}
	_, err = d.sql.ExecContext(ctx, `INSERT INTO invites (code_hash, account_id, created_at, expires_at, hint) VALUES (?, ?, ?, ?, ?)`,
		codeHash, account, d.ms(), expiresAt, hint)
	return expiresAt, err
}

func (d *DB) RegisterWithInvite(ctx context.Context, codeHash []byte, nd NewDevice, maxDevices int) (Account, Device, error) {
	var acct Account
	var dev Device
	err := d.tx(ctx, func(tx *sql.Tx) error {
		now := d.ms()
		var boundTo sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT account_id FROM invites WHERE code_hash = ? AND used_at = 0 AND expires_at > ?`, codeHash, now).Scan(&boundTo)
		if err != nil {
			return notFound(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET used_at = ? WHERE code_hash = ?`, now, codeHash); err != nil {
			return err
		}
		if boundTo.Valid {
			if acct, err = scanAccount(tx.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE id = ?`, boundTo.String)); err != nil {
				return err
			}
		} else {
			acct = Account{ID: newAccountID(), Provider: "invite", CreatedAt: now}
			if _, err := tx.ExecContext(ctx, `INSERT INTO accounts (id, provider, provider_id_hash, created_at) VALUES (?, 'invite', ?, ?)`,
				acct.ID, acct.ID, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE invites SET created_account = ? WHERE code_hash = ?`, acct.ID, codeHash); err != nil {
				return err
			}
		}
		dev, err = addDevice(ctx, tx, now, acct.ID, nd, maxDevices)
		return err
	})
	if errors.Is(err, ErrLimit) {
		return Account{}, Device{}, ErrLimit
	}
	return acct, dev, err
}

func (d *DB) SweepInvites(ctx context.Context) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM invites WHERE (used_at > 0 AND used_at < ? AND created_account IS NULL) OR (used_at = 0 AND expires_at < ?)`,
		d.now().Add(-24*time.Hour).UnixMilli(), d.ms())
	return err
}
