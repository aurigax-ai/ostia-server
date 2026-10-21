package store

import (
	"context"
	"database/sql"
	"errors"
)

type Manifest struct {
	Version   int64
	Blob      []byte
	UpdatedAt int64
}

type VersionMismatchError struct{ Current int64 }

func (e VersionMismatchError) Error() string { return "manifest version mismatch" }

func (e VersionMismatchError) Is(target error) bool { return target == ErrVersionMismatch }

func (d *DB) CurrentManifest(ctx context.Context, accountID string) (Manifest, error) {
	var m Manifest
	err := d.sql.QueryRowContext(ctx, `
		SELECT version, blob, updated_at FROM sync_manifests WHERE account_id = ? ORDER BY version DESC LIMIT 1`, accountID).
		Scan(&m.Version, &m.Blob, &m.UpdatedAt)
	return m, notFound(err)
}

func (d *DB) ManifestAt(ctx context.Context, accountID string, version int64) (Manifest, error) {
	var m Manifest
	err := d.sql.QueryRowContext(ctx, `
		SELECT version, blob, updated_at FROM sync_manifests WHERE account_id = ? AND version = ?`, accountID, version).
		Scan(&m.Version, &m.Blob, &m.UpdatedAt)
	return m, notFound(err)
}

func (d *DB) ManifestVersions(ctx context.Context, accountID string) ([]Manifest, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT version, updated_at FROM sync_manifests WHERE account_id = ? ORDER BY version DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		var m Manifest
		if err := rows.Scan(&m.Version, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func putManifestTx(ctx context.Context, tx *sql.Tx, now int64, accountID string, ifMatch int64, blob []byte, history int) (int64, error) {
	var current int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM sync_manifests WHERE account_id = ?`, accountID).Scan(&current)
	if err != nil {
		return 0, err
	}
	if current != ifMatch {
		return 0, VersionMismatchError{Current: current}
	}
	next := current + 1
	if _, err := tx.ExecContext(ctx, `INSERT INTO sync_manifests (account_id, version, blob, updated_at) VALUES (?, ?, ?, ?)`, accountID, next, blob, now); err != nil {
		return 0, err
	}
	if history > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sync_manifests WHERE account_id = ? AND version <= ?`, accountID, next-int64(history)); err != nil {
			return 0, err
		}
	}
	return next, nil
}

func (d *DB) PutManifest(ctx context.Context, accountID string, ifMatch int64, blob []byte, history int) (int64, error) {
	var next int64
	err := d.tx(ctx, func(tx *sql.Tx) error {
		var err error
		next, err = putManifestTx(ctx, tx, d.ms(), accountID, ifMatch, blob, history)
		return err
	})
	return next, err
}

type Rotation struct {
	IfMatch     int64
	Manifest    []byte
	Wraps       map[string][]byte
	DeleteSlots []string
	History     int
}

func (d *DB) Rotate(ctx context.Context, accountID string, r Rotation) (int64, error) {
	var next int64
	err := d.tx(ctx, func(tx *sql.Tx) error {
		now := d.ms()
		var err error
		next, err = putManifestTx(ctx, tx, now, accountID, r.IfMatch, r.Manifest, r.History)
		if err != nil {
			return err
		}
		for slot, blob := range r.Wraps {
			if err := putWrapTx(ctx, tx, now, accountID, slot, blob); err != nil {
				return err
			}
		}
		for _, slot := range r.DeleteSlots {
			if _, err := tx.ExecContext(ctx, `DELETE FROM key_wraps WHERE account_id = ? AND slot = ?`, accountID, slot); err != nil {
				return err
			}
		}
		return nil
	})
	return next, err
}

func CurrentOf(err error) (int64, bool) {
	if mismatch, ok := errors.AsType[VersionMismatchError](err); ok {
		return mismatch.Current, true
	}
	return 0, false
}
