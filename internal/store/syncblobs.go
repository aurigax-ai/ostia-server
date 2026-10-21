package store

import (
	"context"
	"database/sql"
	"time"
)

type SyncBlob struct {
	ID        string
	Size      int64
	Sum       []byte
	CreatedAt int64
}

func (d *DB) SyncBlob(ctx context.Context, accountID, blobID string) (SyncBlob, error) {
	b := SyncBlob{ID: blobID}
	err := d.sql.QueryRowContext(ctx, `SELECT size, sha256, created_at FROM sync_blobs WHERE account_id = ? AND blob_id = ?`, accountID, blobID).
		Scan(&b.Size, &b.Sum, &b.CreatedAt)
	return b, notFound(err)
}

func (d *DB) AddSyncBlob(ctx context.Context, accountID string, b SyncBlob, quota int64) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		var used int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM sync_blobs WHERE account_id = ?`, accountID).Scan(&used); err != nil {
			return err
		}
		if quota > 0 && used+b.Size > quota {
			return ErrQuota
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sync_blobs (account_id, blob_id, size, sha256, created_at) VALUES (?, ?, ?, ?, ?)`,
			accountID, b.ID, b.Size, b.Sum, d.ms())
		return err
	})
}

func (d *DB) SyncUsage(ctx context.Context, accountID string) (count int, bytes int64, err error) {
	err = d.sql.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM sync_blobs WHERE account_id = ?`, accountID).Scan(&count, &bytes)
	return count, bytes, err
}

func (d *DB) DeleteSyncBlob(ctx context.Context, accountID, blobID string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM sync_blobs WHERE account_id = ? AND blob_id = ?`, accountID, blobID)
	return affected(res, err)
}

func (d *DB) TouchSyncBlob(ctx context.Context, accountID, blobID string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE sync_blobs SET created_at = ? WHERE account_id = ? AND blob_id = ?`, d.ms(), accountID, blobID)
	return err
}

func (d *DB) CollectSyncBlobs(ctx context.Context, accountID string, ifMatch int64, keep map[string]bool, grace time.Duration) ([]string, error) {
	var stale []string
	err := d.tx(ctx, func(tx *sql.Tx) error {
		var current int64
		err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM sync_manifests WHERE account_id = ?`, accountID).Scan(&current)
		if err != nil {
			return err
		}
		if current != ifMatch {
			return VersionMismatchError{Current: current}
		}
		rows, err := tx.QueryContext(ctx, `SELECT blob_id FROM sync_blobs WHERE account_id = ? AND created_at < ?`,
			accountID, d.now().Add(-grace).UnixMilli())
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			if !keep[id] {
				stale = append(stale, id)
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, id := range stale {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sync_blobs WHERE account_id = ? AND blob_id = ?`, accountID, id); err != nil {
				return err
			}
		}
		return nil
	})
	return stale, err
}
