package store

import "context"

func (d *DB) VacuumInto(ctx context.Context, path string) error {
	_, err := d.sql.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}
