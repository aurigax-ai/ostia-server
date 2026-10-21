package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (d *DB) CreateInvite(ctx context.Context, codeHash []byte, accountID string, ttl time.Duration, elevated bool, hint string) (expiresAt int64, err error) {
	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}
	expiresAt = d.now().Add(ttl).UnixMilli()
	var account any
	if accountID != "" {
		account = accountID
	}
	flag := 0
	if elevated {
		flag = 1
	}
	_, err = d.sql.ExecContext(ctx, `INSERT INTO invites (code_hash, account_id, created_at, expires_at, elevated, hint) VALUES (?, ?, ?, ?, ?, ?)`,
		codeHash, account, d.ms(), expiresAt, flag, hint)
	return expiresAt, err
}

func (d *DB) RegisterWithInvite(ctx context.Context, codeHash []byte, nd NewDevice, maxDevices int) (Account, Device, error) {
	var acct Account
	var dev Device
	err := d.tx(ctx, func(tx *sql.Tx) error {
		now := d.ms()
		var boundTo sql.NullString
		var elevated int
		err := tx.QueryRowContext(ctx, `SELECT account_id, elevated FROM invites WHERE code_hash = ? AND used_at = 0 AND expires_at > ?`,
			codeHash, now).Scan(&boundTo, &elevated)
		if err != nil {
			return notFound(err)
		}
		if boundTo.Valid && elevated == 0 {
			var active int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at = 0`, boundTo.String).Scan(&active); err != nil {
				return err
			}
			if active >= 2 {
				return ErrNotFound
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET used_at = ? WHERE code_hash = ?`, now, codeHash); err != nil {
			return err
		}
		if boundTo.Valid {
			acct, err = scanAccount(tx.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE id = ?`, boundTo.String))
		} else {
			acct = Account{ID: newAccountID(), Provider: "invite", CreatedAt: now}
			_, err = tx.ExecContext(ctx, `INSERT INTO accounts (id, provider, provider_id_hash, created_at) VALUES (?, 'invite', ?, ?)`,
				acct.ID, acct.ID, now)
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE invites SET created_account = ? WHERE code_hash = ?`, acct.ID, codeHash)
			}
		}
		if err != nil {
			return err
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

func (d *DB) LiveInvites(ctx context.Context, accountID string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE account_id = ? AND used_at = 0 AND expires_at > ?`, accountID, d.ms()).Scan(&n)
	return n, err
}
