package store

import (
	"context"
	"database/sql"
	"errors"
)

type Manifest struct {
	Version    int64
	KeyVersion int64
	Blob       []byte
	UpdatedAt  int64
}

type VersionMismatchError struct{ Current int64 }

func (e VersionMismatchError) Error() string { return "manifest version mismatch" }

func (e VersionMismatchError) Is(target error) bool { return target == ErrVersionMismatch }

func (d *DB) CurrentManifest(ctx context.Context, accountID string) (Manifest, error) {
	var m Manifest
	err := d.sql.QueryRowContext(ctx, `
		SELECT version, key_version, blob, updated_at FROM sync_manifests WHERE account_id = ? ORDER BY version DESC LIMIT 1`, accountID).
		Scan(&m.Version, &m.KeyVersion, &m.Blob, &m.UpdatedAt)
	return m, notFound(err)
}

func (d *DB) ManifestAt(ctx context.Context, accountID string, version int64) (Manifest, error) {
	var m Manifest
	err := d.sql.QueryRowContext(ctx, `
		SELECT version, key_version, blob, updated_at FROM sync_manifests WHERE account_id = ? AND version = ?`, accountID, version).
		Scan(&m.Version, &m.KeyVersion, &m.Blob, &m.UpdatedAt)
	return m, notFound(err)
}

func (d *DB) ManifestVersions(ctx context.Context, accountID string) ([]Manifest, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT version, key_version, updated_at FROM sync_manifests WHERE account_id = ? ORDER BY version DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		var m Manifest
		if err := rows.Scan(&m.Version, &m.KeyVersion, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func putManifestTx(ctx context.Context, tx *sql.Tx, now int64, accountID string, ifMatch, keyVersion int64, blob []byte, keep Retention) (int64, error) {
	var current int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM sync_manifests WHERE account_id = ?`, accountID).Scan(&current)
	if err != nil {
		return 0, err
	}
	if current != ifMatch {
		return 0, VersionMismatchError{Current: current}
	}
	next := current + 1
	if _, err := tx.ExecContext(ctx, `INSERT INTO sync_manifests (account_id, version, key_version, blob, updated_at) VALUES (?, ?, ?, ?, ?)`, accountID, next, keyVersion, blob, now); err != nil {
		return 0, err
	}
	if keep.Versions > 0 {
		if err := pruneManifests(ctx, tx, now, accountID, keep); err != nil {
			return 0, err
		}
	}
	return next, nil
}

func (d *DB) PutManifest(ctx context.Context, accountID string, ifMatch int64, blob []byte, keep Retention) (int64, error) {
	var next int64
	err := d.tx(ctx, func(tx *sql.Tx) error {
		var keyVersion int64
		err := tx.QueryRowContext(ctx, `SELECT version FROM sync_keys WHERE account_id = ?`, accountID).Scan(&keyVersion)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoKey
		}
		if err != nil {
			return err
		}
		next, err = putManifestTx(ctx, tx, d.ms(), accountID, ifMatch, keyVersion, blob, keep)
		return err
	})
	return next, err
}

type KeyReplacement struct {
	IfMatch    int64
	Manifest   []byte
	Passphrase []byte
	Recovery   []byte
	Retention  Retention
}

func (d *DB) ReplaceKey(ctx context.Context, accountID string, r KeyReplacement) (version, keyVersion int64, err error) {
	err = d.tx(ctx, func(tx *sql.Tx) error {
		now := d.ms()
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM sync_keys WHERE account_id = ?`, accountID).Scan(&keyVersion); err != nil {
			return err
		}
		var err error
		if version, err = putManifestTx(ctx, tx, now, accountID, r.IfMatch, keyVersion, r.Manifest, r.Retention); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO sync_keys (account_id, version, passphrase, recovery, updated_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (account_id) DO UPDATE SET version = excluded.version, passphrase = excluded.passphrase, recovery = excluded.recovery, updated_at = excluded.updated_at`,
			accountID, keyVersion, r.Passphrase, r.Recovery, now)
		return err
	})
	return version, keyVersion, err
}

func CurrentOf(err error) (int64, bool) {
	if mismatch, ok := errors.AsType[VersionMismatchError](err); ok {
		return mismatch.Current, true
	}
	return 0, false
}

const dayMillis = 24 * 60 * 60 * 1000

type Retention struct {
	Versions       int
	CheckpointDays int
}

func pruneManifests(ctx context.Context, tx *sql.Tx, now int64, accountID string, keep Retention) error {
	rows, err := tx.QueryContext(ctx, `SELECT version, updated_at FROM sync_manifests WHERE account_id = ? ORDER BY version DESC`, accountID)
	if err != nil {
		return err
	}
	var drop []int64
	days := map[int64]bool{}
	index := 0
	for rows.Next() {
		var version, updatedAt int64
		if err := rows.Scan(&version, &updatedAt); err != nil {
			_ = rows.Close()
			return err
		}
		day := updatedAt / dayMillis
		switch {
		case index < keep.Versions:
			days[day] = true
		case now-updatedAt <= int64(keep.CheckpointDays)*dayMillis && !days[day]:
			days[day] = true
		default:
			drop = append(drop, version)
		}
		index++
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, version := range drop {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sync_manifests WHERE account_id = ? AND version = ?`, accountID, version); err != nil {
			return err
		}
	}
	return nil
}
