package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type Device struct {
	ID         string
	AccountID  string
	Name       string
	SignPub    []byte
	BoxPub     []byte
	CreatedAt  int64
	LastSeenAt int64
	RevokedAt  int64
}

type NewDevice struct {
	Name    string
	SignPub []byte
	BoxPub  []byte
}

const deviceColumns = `id, account_id, name, sign_pub, box_pub, created_at, last_seen_at, revoked_at`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var v Device
	err := row.Scan(&v.ID, &v.AccountID, &v.Name, &v.SignPub, &v.BoxPub, &v.CreatedAt, &v.LastSeenAt, &v.RevokedAt)
	return v, notFound(err)
}

func (d *DB) Device(ctx context.Context, id string) (Device, error) {
	return scanDevice(d.sql.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id))
}

func (d *DB) DevicesOf(ctx context.Context, accountID string) ([]Device, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE account_id = ? AND revoked_at = 0 ORDER BY created_at`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		v, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

const touchEvery = time.Hour

func (d *DB) TouchDevice(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ? AND last_seen_at <= ?`, d.ms(), id, d.now().Add(-touchEvery).UnixMilli())
	return err
}

func (d *DB) InactiveDevices(ctx context.Context, inactiveAfter time.Duration) ([]Device, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE revoked_at = 0 AND last_seen_at < ?`, d.now().Add(-inactiveAfter).UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		v, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (d *DB) SweepRevokedDevices(ctx context.Context, retention time.Duration) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM devices WHERE revoked_at > 0 AND revoked_at < ?`, d.now().Add(-retention).UnixMilli())
	return err
}

func addDevice(ctx context.Context, tx *sql.Tx, now int64, accountID string, nd NewDevice, maxDevices int) (Device, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at = 0`, accountID).Scan(&count); err != nil {
		return Device{}, err
	}
	if maxDevices > 0 && count >= maxDevices {
		return Device{}, ErrLimit
	}
	dev := Device{ID: ids.New(), AccountID: accountID, Name: nd.Name, SignPub: nd.SignPub, BoxPub: nd.BoxPub, CreatedAt: now, LastSeenAt: now}
	_, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		dev.ID, dev.AccountID, dev.Name, dev.SignPub, dev.BoxPub, dev.CreatedAt, dev.LastSeenAt)
	return dev, err
}

func (d *DB) AddDevice(ctx context.Context, accountID string, nd NewDevice, maxDevices int) (Device, error) {
	var dev Device
	err := d.tx(ctx, func(tx *sql.Tx) error {
		var err error
		dev, err = addDevice(ctx, tx, d.ms(), accountID, nd, maxDevices)
		return err
	})
	return dev, err
}

func (d *DB) RegisterProvider(ctx context.Context, provider, idHash string, nd NewDevice, maxDevices int) (Account, Device, error) {
	var acct Account
	var dev Device
	err := d.tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE provider = ? AND provider_id_hash = ?`, provider, idHash)
		var err error
		acct, err = scanAccount(row)
		if errors.Is(err, ErrNotFound) {
			acct = Account{ID: newAccountID(), Provider: provider, CreatedAt: d.ms()}
			_, err = tx.ExecContext(ctx, `INSERT INTO accounts (id, provider, provider_id_hash, created_at) VALUES (?, ?, ?, ?)`,
				acct.ID, provider, idHash, acct.CreatedAt)
		}
		if err != nil {
			return err
		}
		dev, err = addDevice(ctx, tx, d.ms(), acct.ID, nd, maxDevices)
		return err
	})
	return acct, dev, err
}

func (d *DB) RevokeDevice(ctx context.Context, accountID, id string) (label string, err error) {
	return d.revoke(ctx, accountID, id, 0)
}

func (d *DB) RevokeInactiveDevice(ctx context.Context, accountID, id string, silentSince int64) error {
	_, err := d.revoke(ctx, accountID, id, silentSince)
	return err
}

func (d *DB) revoke(ctx context.Context, accountID, id string, silentSince int64) (label string, err error) {
	err = d.tx(ctx, func(tx *sql.Tx) error {
		query := `UPDATE devices SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at = 0`
		args := []any{d.ms(), id, accountID}
		if silentSince > 0 {
			query += ` AND last_seen_at < ?`
			args = append(args, silentSince)
		}
		res, err := tx.ExecContext(ctx, query, args...)
		if err := affected(res, err); err != nil {
			return err
		}
		err = tx.QueryRowContext(ctx, `SELECT label FROM relay_labels WHERE device_id = ?`, id).Scan(&label)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		for _, q := range []string{
			`DELETE FROM sessions WHERE device_id = ?`,
			`DELETE FROM relay_labels WHERE device_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM key_wraps WHERE account_id = ? AND slot = ?`, accountID, DeviceSlot(id))
		return err
	})
	return label, err
}

func DeviceSlot(deviceID string) string { return "device:" + deviceID }

func (d *DB) AdvanceSigningCounter(ctx context.Context, deviceID string, ms int64) (bool, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE devices SET last_signed_ms = ? WHERE id = ? AND last_signed_ms < ?`, ms, deviceID, ms)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
