package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type Approval struct {
	ID                string
	AccountID         string
	RequesterDeviceID string
	RequesterName     string
	RequesterCreated  int64
	CreatedAt         int64
	ExpiresAt         int64
	ApprovedAt        int64
}

func (d *DB) CreateApproval(ctx context.Context, accountID, deviceID string, tokenHash []byte, ttl time.Duration) (Approval, error) {
	a := Approval{ID: ids.New(), AccountID: accountID, RequesterDeviceID: deviceID, CreatedAt: d.ms(), ExpiresAt: d.now().Add(ttl).UnixMilli()}
	err := d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM approvals WHERE requester_token_hash = ? OR expires_at <= ?`, tokenHash, a.CreatedAt); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO approvals (id, account_id, requester_device_id, requester_token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			a.ID, accountID, deviceID, tokenHash, a.CreatedAt, a.ExpiresAt)
		return err
	})
	return a, err
}

func (d *DB) PendingApprovals(ctx context.Context, accountID, exceptDeviceID string) ([]Approval, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT a.id, a.account_id, a.requester_device_id, v.name, v.created_at, a.created_at, a.expires_at
		FROM approvals a JOIN devices v ON v.id = a.requester_device_id
		WHERE a.account_id = ? AND a.requester_device_id != ? AND a.approved_at = 0 AND a.expires_at > ?
		ORDER BY a.created_at`, accountID, exceptDeviceID, d.ms())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.AccountID, &a.RequesterDeviceID, &a.RequesterName, &a.RequesterCreated, &a.CreatedAt, &a.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) ApprovalOf(ctx context.Context, id string, tokenHash []byte) (Approval, error) {
	a := Approval{ID: id}
	err := d.sql.QueryRowContext(ctx, `
		SELECT account_id, requester_device_id, created_at, expires_at, approved_at FROM approvals
		WHERE id = ? AND requester_token_hash = ? AND expires_at > ?`, id, tokenHash, d.ms()).
		Scan(&a.AccountID, &a.RequesterDeviceID, &a.CreatedAt, &a.ExpiresAt, &a.ApprovedAt)
	return a, notFound(err)
}

func (d *DB) PendingApproval(ctx context.Context, id, accountID string) (Approval, error) {
	a := Approval{ID: id, AccountID: accountID}
	err := d.sql.QueryRowContext(ctx, `
		SELECT requester_device_id, created_at, expires_at FROM approvals
		WHERE id = ? AND account_id = ? AND approved_at = 0 AND expires_at > ?`, id, accountID, d.ms()).
		Scan(&a.RequesterDeviceID, &a.CreatedAt, &a.ExpiresAt)
	return a, notFound(err)
}

func (d *DB) Approve(ctx context.Context, id, accountID, approverDeviceID string, elevatedUntil int64, minRequesterAge time.Duration) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		var requesterDevice string
		var tokenHash []byte
		err := tx.QueryRowContext(ctx, `
			SELECT requester_device_id, requester_token_hash FROM approvals
			WHERE id = ? AND account_id = ? AND approved_at = 0 AND expires_at > ?`, id, accountID, d.ms()).Scan(&requesterDevice, &tokenHash)
		if err != nil {
			return notFound(err)
		}
		if requesterDevice == approverDeviceID {
			return ErrConflict
		}
		var requesterCreated int64
		if err := tx.QueryRowContext(ctx, `SELECT created_at FROM devices WHERE id = ?`, requesterDevice).Scan(&requesterCreated); err != nil {
			return notFound(err)
		}
		if minRequesterAge > 0 && d.now().Sub(time.UnixMilli(requesterCreated)) < minRequesterAge {
			return ErrRequesterTooNew
		}
		if _, err := tx.ExecContext(ctx, `UPDATE approvals SET approved_at = ? WHERE id = ?`, d.ms(), id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET elevated_until = ? WHERE token_hash = ?`, elevatedUntil, tokenHash)
		return affected(res, err)
	})
}

func (d *DB) DeleteApproval(ctx context.Context, id, accountID, requesterDeviceID string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM approvals WHERE id = ? AND account_id = ? AND requester_device_id = ?`, id, accountID, requesterDeviceID)
	return affected(res, err)
}

func (d *DB) SweepApprovals(ctx context.Context) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM approvals WHERE expires_at <= ?`, d.ms())
	return err
}

func (d *DB) ActiveDeviceCount(ctx context.Context, accountID string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at = 0`, accountID).Scan(&n)
	return n, err
}
