package store

import (
	"context"
	"database/sql"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type Account struct {
	ID              string
	Provider        string
	CreatedAt       int64
	PublishDisabled bool
}

func scanAccount(row interface{ Scan(...any) error }) (Account, error) {
	var a Account
	var disabled int
	err := row.Scan(&a.ID, &a.Provider, &a.CreatedAt, &disabled)
	a.PublishDisabled = disabled != 0
	return a, notFound(err)
}

const accountColumns = `id, provider, created_at, publish_disabled`

func (d *DB) Account(ctx context.Context, id string) (Account, error) {
	return scanAccount(d.sql.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE id = ?`, id))
}

func (d *DB) ProviderIdentity(ctx context.Context, id string) (provider, idHash string, err error) {
	err = d.sql.QueryRowContext(ctx, `SELECT provider, provider_id_hash FROM accounts WHERE id = ?`, id).Scan(&provider, &idHash)
	return provider, idHash, notFound(err)
}

func (d *DB) Accounts(ctx context.Context) ([]Account, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+accountColumns+` FROM accounts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) SetPublishDisabled(ctx context.Context, id string, disabled bool) error {
	flag := 0
	if disabled {
		flag = 1
	}
	res, err := d.sql.ExecContext(ctx, `UPDATE accounts SET publish_disabled = ? WHERE id = ?`, flag, id)
	return affected(res, err)
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) BlobKeysOf(ctx context.Context, accountID string) ([]string, error) {
	var keys []string
	rows, err := d.sql.QueryContext(ctx, `SELECT blob_id FROM sync_blobs WHERE account_id = ?`, accountID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		keys = append(keys, SyncBlobKey(accountID, id))
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	shares, err := d.sql.QueryContext(ctx, `SELECT id FROM shares WHERE account_id = ? AND uploaded_at > 0`, accountID)
	if err != nil {
		return nil, err
	}
	defer shares.Close()
	for shares.Next() {
		var id string
		if err := shares.Scan(&id); err != nil {
			return nil, err
		}
		keys = append(keys, ShareBlobKey(id))
	}
	return keys, shares.Err()
}

func (d *DB) DeleteAccount(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, id)
	return affected(res, err)
}

func (d *DB) PurgeDeparted(ctx context.Context, accountID string) (blobKeys []string, accountDeleted bool, err error) {
	err = d.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT blob_id FROM sync_blobs WHERE account_id = ?`, accountID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			blobKeys = append(blobKeys, SyncBlobKey(accountID, id))
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM sync_blobs WHERE account_id = ?`,
			`DELETE FROM sync_manifests WHERE account_id = ?`,
			`DELETE FROM key_wraps WHERE account_id = ?`,
			`DELETE FROM push_handles WHERE account_id = ?`,
			`DELETE FROM push_tickets WHERE account_id = ?`,
			`DELETE FROM invites WHERE account_id = ? AND used_at = 0`,
		} {
			if _, err := tx.ExecContext(ctx, q, accountID); err != nil {
				return err
			}
		}
		var shares int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM shares WHERE account_id = ?`, accountID).Scan(&shares); err != nil {
			return err
		}
		if shares > 0 {
			return nil
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, accountID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		accountDeleted = n == 1
		return err
	})
	return blobKeys, accountDeleted, err
}

func SyncBlobKey(accountID, blobID string) string { return "sync/" + accountID + "/" + blobID }

func ShareBlobKey(shareID string) string { return "share/" + shareID }

func newAccountID() string { return ids.New() }
