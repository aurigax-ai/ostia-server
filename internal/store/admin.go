package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

type AuditEntry struct {
	At     int64
	Admin  string
	Action string
	Target string
	Count  int
}

type AdminIdentity struct {
	GitHubID int64
	Login    string
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
	LastSeenAt int64
	Bytes      int64
	InviteHint string
}

const maxUsedInvitesListed = 50

var ErrAdminExists = errors.New("an admin already exists")

func (d *DB) HasAdmin(ctx context.Context) (bool, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n > 0, err
}

func (d *DB) CreateSetupCode(ctx context.Context, hash []byte, hint string, ttl time.Duration) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if exists, err := adminExists(ctx, tx); err != nil {
			return err
		} else if exists {
			return ErrAdminExists
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM admin_codes`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO admin_codes (code_hash, hint, expires_at) VALUES (?, ?, ?)`, hash, hint, d.now().Add(ttl).UnixMilli())
		return err
	})
}

func (d *DB) SetupCodeValid(ctx context.Context, hash []byte) error {
	var one int
	err := d.sql.QueryRowContext(ctx, `SELECT 1 FROM admin_codes WHERE code_hash = ? AND used_at = 0 AND expires_at > ?`, hash, d.ms()).Scan(&one)
	return notFound(err)
}

func (d *DB) ClaimFirstAdmin(ctx context.Context, codeHash []byte, githubID int64, login string, tokenHash []byte, ttl time.Duration) (hint string, err error) {
	err = d.tx(ctx, func(tx *sql.Tx) error {
		if exists, err := adminExists(ctx, tx); err != nil {
			return err
		} else if exists {
			return ErrAdminExists
		}
		err := tx.QueryRowContext(ctx, `UPDATE admin_codes SET used_at = ? WHERE code_hash = ? AND used_at = 0 AND expires_at > ? RETURNING hint`, d.ms(), codeHash, d.ms()).Scan(&hint)
		if err != nil {
			return notFound(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO admins (github_id, login, created_at) VALUES (?, ?, ?)`, githubID, login, d.ms()); err != nil {
			return err
		}
		return d.insertAdminSession(ctx, tx, tokenHash, githubID, ttl)
	})
	return hint, err
}

func adminExists(ctx context.Context, tx *sql.Tx) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n > 0, err
}

func (d *DB) SignInAdmin(ctx context.Context, githubID int64, login string, tokenHash []byte, ttl time.Duration) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE admins SET login = ? WHERE github_id = ?`, login, githubID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return ErrNotFound
		}
		return d.insertAdminSession(ctx, tx, tokenHash, githubID, ttl)
	})
}

func (d *DB) insertAdminSession(ctx context.Context, tx *sql.Tx, tokenHash []byte, githubID int64, ttl time.Duration) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO admin_sessions (token_hash, admin, github_id, expires_at) VALUES (?, ?, ?, ?)`, tokenHash, "github:"+strconv.FormatInt(githubID, 10), githubID, d.now().Add(ttl).UnixMilli())
	return err
}

func (d *DB) ResetAdmins(ctx context.Context) (admins, sessions int64, err error) {
	err = d.tx(ctx, func(tx *sql.Tx) error {
		for _, step := range []struct {
			query string
			n     *int64
		}{
			{`DELETE FROM admins`, &admins},
			{`DELETE FROM admin_sessions`, &sessions},
			{`DELETE FROM admin_codes`, nil},
			{`DELETE FROM admin_oauth`, nil},
		} {
			res, err := tx.ExecContext(ctx, step.query)
			if err != nil {
				return err
			}
			if step.n != nil {
				if *step.n, err = res.RowsAffected(); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return admins, sessions, err
}

func (d *DB) CreateAdminOAuth(ctx context.Context, stateHash []byte, verifier string, codeHash []byte, ttl time.Duration) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_oauth (state_hash, verifier, code_hash, expires_at) VALUES (?, ?, ?, ?)`, stateHash, verifier, codeHash, d.now().Add(ttl).UnixMilli())
	return err
}

func (d *DB) TakeAdminOAuth(ctx context.Context, stateHash []byte) (verifier string, codeHash []byte, err error) {
	err = d.sql.QueryRowContext(ctx, `DELETE FROM admin_oauth WHERE state_hash = ? AND expires_at > ? RETURNING verifier, code_hash`, stateHash, d.ms()).Scan(&verifier, &codeHash)
	return verifier, codeHash, notFound(err)
}

func (d *DB) AdminSession(ctx context.Context, tokenHash []byte) (AdminIdentity, error) {
	var who AdminIdentity
	err := d.sql.QueryRowContext(ctx, `SELECT a.github_id, a.login FROM admin_sessions s JOIN admins a ON a.github_id = s.github_id WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, d.ms()).Scan(&who.GitHubID, &who.Login)
	return who, notFound(err)
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM admin_oauth WHERE expires_at <= ?`, d.ms()); err != nil {
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

const countWindow = time.Minute

func (d *DB) CountAudit(ctx context.Context, admin, action, target string) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE admin_audit SET count = count + 1, at = ? WHERE id = (SELECT MAX(id) FROM admin_audit WHERE admin = ? AND action = ? AND target = ? AND at > ?)`, d.ms(), admin, action, target, d.now().Add(-countWindow).UnixMilli())
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n > 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO admin_audit (at, admin, action, target) VALUES (?, ?, ?, ?)`, d.ms(), admin, action, target)
		return err
	})
}

func (d *DB) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT at, admin, action, target, count FROM admin_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.Admin, &e.Action, &e.Target, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) AdminInvites(ctx context.Context) (open, used []AdminInvite, err error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT hex(code_hash), hint, created_at, expires_at, used_at, COALESCE(created_account, '')
		FROM invites ORDER BY created_at DESC`)
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
		case v.ExpiresAt > now:
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
	err = d.sql.QueryRowContext(ctx, `DELETE FROM invites WHERE code_hash = ? AND used_at = 0 RETURNING hint`, raw).Scan(&hint)
	return hint, notFound(err)
}

func (d *DB) AccountSummaries(ctx context.Context) ([]AccountSummary, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT a.id, a.created_at,
			(SELECT COUNT(*) FROM devices v WHERE v.account_id = a.id AND v.revoked_at = 0),
			(SELECT COALESCE(MAX(v.last_seen_at), 0) FROM devices v WHERE v.account_id = a.id AND v.revoked_at = 0),
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
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.Devices, &s.LastSeenAt, &s.Bytes, &s.InviteHint); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
