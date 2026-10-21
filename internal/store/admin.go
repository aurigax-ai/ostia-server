package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"
)

type AuditEntry struct {
	At     int64
	Admin  string
	Action string
	Target string
}

type AdminInvite struct {
	ID             string
	Hint           string
	CreatedAt      int64
	ExpiresAt      int64
	UsedAt         int64
	CreatedAccount string
}

type AccountSummary struct {
	ID         string
	CreatedAt  int64
	Devices    int
	LastSeen   int64
	Bytes      int64
	InviteHint string
}

const maxUsedInvitesListed = 50

func (d *DB) CreateAdminCode(ctx context.Context, hash []byte, hint string, ttl time.Duration) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_codes (code_hash, hint, expires_at) VALUES (?, ?, ?)`, hash, hint, d.now().Add(ttl).UnixMilli())
	return err
}

func (d *DB) ConsumeAdminCode(ctx context.Context, hash []byte) (hint string, err error) {
	err = d.sql.QueryRowContext(ctx, `UPDATE admin_codes SET used_at = ? WHERE code_hash = ? AND used_at = 0 AND expires_at > ? RETURNING hint`, d.ms(), hash, d.ms()).Scan(&hint)
	return hint, notFound(err)
}

func (d *DB) CreateAdminSession(ctx context.Context, tokenHash []byte, admin string, ttl time.Duration) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_sessions (token_hash, admin, expires_at) VALUES (?, ?, ?)`, tokenHash, admin, d.now().Add(ttl).UnixMilli())
	return err
}

func (d *DB) AdminSession(ctx context.Context, tokenHash []byte) (admin string, err error) {
	err = d.sql.QueryRowContext(ctx, `SELECT admin FROM admin_sessions WHERE token_hash = ? AND expires_at > ?`, tokenHash, d.ms()).Scan(&admin)
	return admin, notFound(err)
}

func (d *DB) DeleteAdminSession(ctx context.Context, tokenHash []byte) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (d *DB) DeleteAdminSessions(ctx context.Context) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM admin_sessions`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) SweepAdmin(ctx context.Context) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at <= ?`, d.ms()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM admin_codes WHERE expires_at <= ?`, d.ms())
		return err
	})
}

func (d *DB) AddAudit(ctx context.Context, admin, action, target string) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_audit (at, admin, action, target) VALUES (?, ?, ?, ?)`, d.ms(), admin, action, target)
	return err
}

func (d *DB) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT at, admin, action, target FROM admin_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.Admin, &e.Action, &e.Target); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) AdminInvites(ctx context.Context) (open, used []AdminInvite, err error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT hex(code_hash), hint, created_at, expires_at, used_at, COALESCE(created_account, '')
		FROM invites WHERE account_id IS NULL ORDER BY created_at DESC`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	now := d.ms()
	for rows.Next() {
		var v AdminInvite
		if err := rows.Scan(&v.ID, &v.Hint, &v.CreatedAt, &v.ExpiresAt, &v.UsedAt, &v.CreatedAccount); err != nil {
			return nil, nil, err
		}
		v.ID = strings.ToLower(v.ID)
		switch {
		case v.UsedAt > 0:
			if len(used) < maxUsedInvitesListed {
				used = append(used, v)
			}
		case v.ExpiresAt == 0 || v.ExpiresAt > now:
			open = append(open, v)
		}
	}
	return open, used, rows.Err()
}

func (d *DB) RevokeInvite(ctx context.Context, id string) (hint string, err error) {
	raw, err := hex.DecodeString(id)
	if err != nil {
		return "", ErrNotFound
	}
	err = d.sql.QueryRowContext(ctx, `DELETE FROM invites WHERE code_hash = ? AND account_id IS NULL AND used_at = 0 RETURNING hint`, raw).Scan(&hint)
	return hint, notFound(err)
}

func (d *DB) AccountSummaries(ctx context.Context) ([]AccountSummary, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT a.id, a.created_at,
			(SELECT COUNT(*) FROM devices v WHERE v.account_id = a.id AND v.revoked_at = 0),
			(SELECT COALESCE(MAX(v.last_seen), 0) FROM devices v WHERE v.account_id = a.id AND v.revoked_at = 0),
			(SELECT COALESCE(SUM(b.size), 0) FROM sync_blobs b WHERE b.account_id = a.id),
			COALESCE((SELECT i.hint FROM invites i WHERE i.created_account = a.id), '')
		FROM accounts a ORDER BY 4 DESC, a.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountSummary
	for rows.Next() {
		var s AccountSummary
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.Devices, &s.LastSeen, &s.Bytes, &s.InviteHint); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
