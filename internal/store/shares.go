package store

import (
	"context"
	"database/sql"
	"time"
)

type Share struct {
	ID              string
	AccountID       string
	Mode            string
	Salt            []byte
	Size            int64
	CreatedAt       int64
	ExpiresAt       int64
	Views           int64
	DeleteTokenHash []byte
	UploadedAt      int64
	RemovedAt       int64
}

type ShareQuota struct {
	MaxShares int
	MaxBytes  int64
}

const shareColumns = `id, account_id, mode, salt, size, created_at, expires_at, views, delete_token_hash, uploaded_at, removed_at`

func scanShare(row interface{ Scan(...any) error }) (Share, error) {
	var s Share
	err := row.Scan(&s.ID, &s.AccountID, &s.Mode, &s.Salt, &s.Size, &s.CreatedAt, &s.ExpiresAt, &s.Views, &s.DeleteTokenHash, &s.UploadedAt, &s.RemovedAt)
	return s, notFound(err)
}

func (d *DB) CreateShare(ctx context.Context, s Share, quota ShareQuota) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		var count int
		var bytes int64
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM shares WHERE account_id = ? AND removed_at = 0`, s.AccountID).Scan(&count, &bytes)
		if err != nil {
			return err
		}
		if quota.MaxShares > 0 && count >= quota.MaxShares {
			return ErrQuota
		}
		if quota.MaxBytes > 0 && bytes+s.Size > quota.MaxBytes {
			return ErrQuota
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shares (`+shareColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0)`,
			s.ID, s.AccountID, s.Mode, s.Salt, s.Size, d.ms(), s.ExpiresAt, s.DeleteTokenHash)
		return err
	})
}

func (d *DB) Share(ctx context.Context, id string) (Share, error) {
	return scanShare(d.sql.QueryRowContext(ctx, `SELECT `+shareColumns+` FROM shares WHERE id = ?`, id))
}

func (d *DB) SharesOf(ctx context.Context, accountID string) ([]Share, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+shareColumns+` FROM shares WHERE account_id = ? AND removed_at = 0 ORDER BY created_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		s, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) MarkUploaded(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE shares SET uploaded_at = ? WHERE id = ? AND uploaded_at = 0 AND removed_at = 0`, d.ms(), id)
	if err := affected(res, err); err != nil {
		return ErrConflict
	}
	return nil
}

func (d *DB) CountView(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE shares SET views = views + 1 WHERE id = ?`, id)
	return err
}

func (d *DB) DeleteShare(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM shares WHERE id = ?`, id)
	return affected(res, err)
}

func (d *DB) TakeDown(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE shares SET removed_at = ? WHERE id = ? AND removed_at = 0`, d.ms(), id)
	return affected(res, err)
}

func (d *DB) SweepableShares(ctx context.Context, staleUpload time.Duration) ([]Share, error) {
	now := d.ms()
	rows, err := d.sql.QueryContext(ctx, `
		SELECT `+shareColumns+` FROM shares
		WHERE (expires_at > 0 AND expires_at <= ?)
		   OR (uploaded_at = 0 AND created_at < ?)`, now, d.now().Add(-staleUpload).UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		s, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) AddReport(ctx context.Context, shareID, reason string) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO reports (share_id, reason_code, created_at) VALUES (?, ?, ?)`, shareID, reason, d.ms())
	return err
}

type ReportSummary struct {
	ShareID   string
	Reports   int
	Latest    int64
	AccountID string
	Removed   bool
}

func (d *DB) ReportSummaries(ctx context.Context) ([]ReportSummary, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT r.share_id, COUNT(*), MAX(r.created_at), COALESCE(s.account_id, ''), COALESCE(s.removed_at, 1) > 0
		FROM reports r LEFT JOIN shares s ON s.id = r.share_id
		GROUP BY r.share_id ORDER BY MAX(r.created_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportSummary
	for rows.Next() {
		var r ReportSummary
		if err := rows.Scan(&r.ShareID, &r.Reports, &r.Latest, &r.AccountID, &r.Removed); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
