package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type Device struct {
	ID        string
	AccountID string
	Name      string
	SignPub   []byte
	BoxPub    []byte
	CreatedAt int64
	LastSeen  int64
	RevokedAt int64
}

type NewDevice struct {
	Name    string
	SignPub []byte
	BoxPub  []byte
}

const deviceColumns = `id, account_id, name, sign_pub, box_pub, created_at, last_seen, revoked_at`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var v Device
	err := row.Scan(&v.ID, &v.AccountID, &v.Name, &v.SignPub, &v.BoxPub, &v.CreatedAt, &v.LastSeen, &v.RevokedAt)
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

func (d *DB) TouchDevice(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE id = ?`, d.ms(), id)
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
	dev := Device{ID: ids.New(), AccountID: accountID, Name: nd.Name, SignPub: nd.SignPub, BoxPub: nd.BoxPub, CreatedAt: now, LastSeen: now}
	_, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		dev.ID, dev.AccountID, dev.Name, dev.SignPub, dev.BoxPub, dev.CreatedAt, dev.LastSeen)
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
	err = d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at = 0`, d.ms(), id, accountID)
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

func (d *DB) UnseenDevices(ctx context.Context, viewer Device) (map[string]bool, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT v.id FROM devices v
		WHERE v.account_id = ? AND v.revoked_at = 0 AND v.id != ? AND v.created_at >= ?
		  AND NOT EXISTS (SELECT 1 FROM device_seen s WHERE s.viewer_device_id = ? AND s.device_id = v.id)`,
		viewer.AccountID, viewer.ID, viewer.CreatedAt, viewer.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (d *DB) MarkSeen(ctx context.Context, viewerDeviceID, deviceID string) error {
	_, err := d.sql.ExecContext(ctx, `INSERT OR IGNORE INTO device_seen (viewer_device_id, device_id) VALUES (?, ?)`, viewerDeviceID, deviceID)
	return err
}

func (d *DB) OlderActiveDevices(ctx context.Context, device Device) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM devices
		WHERE account_id = ? AND revoked_at = 0 AND id != ? AND (created_at < ? OR (created_at = ? AND id < ?))`,
		device.AccountID, device.ID, device.CreatedAt, device.CreatedAt, device.ID).Scan(&n)
	return n, err
}

func (d *DB) AdvanceSigningCounter(ctx context.Context, deviceID string, ms int64) (bool, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE devices SET last_signed_ms = ? WHERE id = ? AND last_signed_ms < ?`, ms, deviceID, ms)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
