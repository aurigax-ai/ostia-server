package store

import "context"

type SyncKey struct {
	Version    int64
	Passphrase []byte
	Recovery   []byte
	UpdatedAt  int64
}

func (d *DB) SyncKey(ctx context.Context, accountID string) (SyncKey, error) {
	var k SyncKey
	err := d.sql.QueryRowContext(ctx, `SELECT version, passphrase, recovery, updated_at FROM sync_keys WHERE account_id = ?`, accountID).
		Scan(&k.Version, &k.Passphrase, &k.Recovery, &k.UpdatedAt)
	return k, notFound(err)
}
