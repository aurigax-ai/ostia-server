package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type Label struct {
	Label     string
	DeviceID  string
	AccountID string
}

func (d *DB) LabelFor(ctx context.Context, deviceID, accountID string) (string, error) {
	var label string
	err := d.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT label FROM relay_labels WHERE device_id = ?`, deviceID).Scan(&label)
		if errors.Is(err, sql.ErrNoRows) {
			label = ids.New()
			_, err = tx.ExecContext(ctx, `INSERT INTO relay_labels (label, device_id, account_id) VALUES (?, ?, ?)`, label, deviceID, accountID)
		}
		return err
	})
	return label, err
}

func (d *DB) LabelOwner(ctx context.Context, label string) (Label, error) {
	l := Label{Label: label}
	err := d.sql.QueryRowContext(ctx, `SELECT device_id, account_id FROM relay_labels WHERE label = ?`, label).Scan(&l.DeviceID, &l.AccountID)
	return l, notFound(err)
}

func (d *DB) AddRelayBytes(ctx context.Context, label, month string, n int64) error {
	_, err := d.sql.ExecContext(ctx, `
		UPDATE relay_labels SET
			bytes_month = CASE WHEN month = ? THEN bytes_month + ? ELSE ? END,
			month = ?
		WHERE label = ?`, month, n, n, month, label)
	return err
}

func (d *DB) AccountRelayBytes(ctx context.Context, accountID, month string) (int64, error) {
	var n int64
	err := d.sql.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes_month), 0) FROM relay_labels WHERE account_id = ? AND month = ?`, accountID, month).Scan(&n)
	return n, err
}

func (d *DB) Month() string { return d.now().UTC().Format("2006-01") }
