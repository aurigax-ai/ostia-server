package store

import "context"

func (d *DB) VacuumInto(ctx context.Context, path string) error {
	_, err := d.sql.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

func (d *DB) CheckpointWAL(ctx context.Context) error {
	var busy, frames, done int
	return d.sql.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done)
}
