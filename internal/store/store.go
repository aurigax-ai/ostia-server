package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrVersionMismatch = errors.New("version mismatch")
	ErrQuota           = errors.New("quota exceeded")
	ErrLimit           = errors.New("limit reached")
	ErrGone            = errors.New("gone")
	ErrRequesterTooNew = errors.New("requester too new")
	ErrInvalidTTL      = errors.New("ttl must be positive")
)

const (
	fileMode      = 0o600
	JournalWAL    = "wal"
	JournalDelete = "delete"
)

func ValidJournal(mode string) bool { return mode == JournalWAL || mode == JournalDelete }

var migrations = []string{schemaV1}

type DB struct {
	sql *sql.DB
	now func() time.Time
}

func Open(path, journal string, now func() time.Time) (*DB, error) {
	if !ValidJournal(journal) {
		return nil, fmt.Errorf("unknown sqlite journal mode %q", journal)
	}
	if err := restrictFiles(path); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode("+journal+")")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "secure_delete(1)")
	q.Set("_txlock", "immediate")
	conn, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(8)
	d := &DB{sql: conn, now: now}
	if err := d.migrate(context.Background()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return d, nil
}

func restrictFiles(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Chmod(path+suffix, fileMode); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (d *DB) Close() error { return d.sql.Close() }

func (d *DB) ms() int64 { return d.now().UnixMilli() }

func (d *DB) migrate(ctx context.Context) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		var version int
		if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
			return err
		}
		if version > len(migrations) {
			return fmt.Errorf("database schema version %d is newer than this build supports (%d)", version, len(migrations))
		}
		for i := version; i < len(migrations); i++ {
			if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
				return fmt.Errorf("migration %d: %w", i+1, err)
			}
		}
		_, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)))
		return err
	})
}

func (d *DB) tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
