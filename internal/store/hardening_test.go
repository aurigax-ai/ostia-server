package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

func TestDatabaseFilesAreOwnerOnlyEvenWhenTheyAlreadyExistWiderOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Open(path, JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	register(t, d, "github", "h")
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s is %o, want 600", filepath.Base(name), info.Mode().Perm())
		}
	}
}

func TestDeletedRowsAreOverwrittenOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	d, err := Open(path, JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var on int
	if err := d.sql.QueryRow(`PRAGMA secure_delete`).Scan(&on); err != nil || on != 1 {
		t.Fatalf("secure_delete is %d: %v", on, err)
	}
	const marker = "Distinctive-Device-Name-For-Remanence-Check"
	a, _, err := d.RegisterProvider(t.Context(), "github", "h", NewDevice{Name: marker, SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.sql.Exec(`DELETE FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("a deleted device name is still readable in the database file")
	}
}

func TestLastSeenIsStoredAsTheDayOnly(t *testing.T) {
	d, c := open(t)
	c.t = time.Date(2026, 10, 21, 15, 42, 7, 0, time.UTC)
	_, dev := register(t, d, "github", "h")
	midnight := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC).UnixMilli()
	if dev.LastSeen != midnight {
		t.Fatalf("a new device's last seen carries the time of day: %d", dev.LastSeen)
	}
	c.t = c.t.Add(3 * time.Hour)
	if err := d.TouchDevice(t.Context(), dev.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Device(t.Context(), dev.ID)
	if got.LastSeen != midnight {
		t.Fatalf("a touch later the same day moved last seen: %d", got.LastSeen)
	}
	c.t = time.Date(2026, 10, 23, 1, 2, 3, 0, time.UTC)
	if err := d.TouchDevice(t.Context(), dev.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = d.Device(t.Context(), dev.ID)
	if want := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC).UnixMilli(); got.LastSeen != want {
		t.Fatalf("last seen %d, want %d", got.LastSeen, want)
	}
}

func TestRevokedDevicesAreDeletedAfterTheRetention(t *testing.T) {
	d, c := open(t)
	a, old := register(t, d, "github", "h")
	_, err := d.AddDevice(t.Context(), a.ID, newDevice("recent"), 10)
	if err != nil {
		t.Fatal(err)
	}
	recent, _ := d.DevicesOf(t.Context(), a.ID)
	keep := recent[len(recent)-1]
	active, _ := d.AddDevice(t.Context(), a.ID, newDevice("active"), 10)
	if _, err := d.RevokeDevice(t.Context(), a.ID, old.ID); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(20 * 24 * time.Hour)
	if _, err := d.RevokeDevice(t.Context(), a.ID, keep.ID); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(15 * 24 * time.Hour)
	if err := d.SweepRevokedDevices(t.Context(), 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Device(t.Context(), old.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a device revoked 35 days ago survived: %v", err)
	}
	if _, err := d.Device(t.Context(), keep.ID); err != nil {
		t.Fatalf("a device revoked 15 days ago was deleted: %v", err)
	}
	if _, err := d.Device(t.Context(), active.ID); err != nil {
		t.Fatalf("an active device was deleted: %v", err)
	}
}

func TestInvitesRefuseANonPositiveTTL(t *testing.T) {
	d, _ := open(t)
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := d.CreateInvite(t.Context(), ids.Hash("code"), "", ttl, false, ""); !errors.Is(err, ErrInvalidTTL) {
			t.Fatalf("ttl %v: %v", ttl, err)
		}
	}
}

func TestInvitesWithoutAnExpiryDoNotWorkAndAreSwept(t *testing.T) {
	d, _ := open(t)
	if _, err := d.sql.Exec(`INSERT INTO invites (code_hash, account_id, created_at, expires_at, elevated) VALUES (?, NULL, 1, 0, 0)`, ids.Hash("legacy")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), ids.Hash("legacy"), newDevice("x"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an invite that never expires was accepted: %v", err)
	}
	if err := d.SweepInvites(t.Context()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.sql.QueryRow(`SELECT COUNT(*) FROM invites`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d invites left: %v", n, err)
	}
}

func TestVacuumIntoWritesAConsistentCopy(t *testing.T) {
	d, _ := open(t)
	register(t, d, "github", "h")
	out := filepath.Join(t.TempDir(), "copy.sqlite")
	if err := d.VacuumInto(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	copyDB, err := Open(out, JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = copyDB.Close() })
	accounts, err := copyDB.Accounts(t.Context())
	if err != nil || len(accounts) != 1 {
		t.Fatalf("%v %v", accounts, err)
	}
	if err := d.VacuumInto(t.Context(), out); err == nil {
		t.Fatal("an existing file was overwritten")
	}
}

func pragma(t *testing.T, d *DB, name string) string {
	t.Helper()
	var v string
	if err := d.sql.QueryRow(`PRAGMA ` + name).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestJournalModeFollowsTheSettingAndKeepsTheBusyTimeout(t *testing.T) {
	for mode, want := range map[string]string{JournalWAL: "wal", JournalDelete: "delete"} {
		path := filepath.Join(t.TempDir(), "db.sqlite")
		d, err := Open(path, mode, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		register(t, d, "github", "h")
		if got := pragma(t, d, "journal_mode"); got != want {
			t.Errorf("%s: journal_mode is %q", mode, got)
		}
		if got := pragma(t, d, "busy_timeout"); got != "5000" {
			t.Errorf("%s: busy_timeout is %q", mode, got)
		}
		_, walErr := os.Stat(path + "-wal")
		if (walErr == nil) != (mode == JournalWAL) {
			t.Errorf("%s: wal file present=%v", mode, walErr == nil)
		}
		_ = d.Close()
	}
}

func TestUnknownJournalModesAreRefused(t *testing.T) {
	for _, mode := range []string{"", "truncate", "WAL", "memory", "wal); drop table accounts; --"} {
		if _, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), mode, time.Now); err == nil {
			t.Errorf("%q was accepted", mode)
		}
	}
}

func TestADatabaseInWALModeConvertsToDeleteMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	d, err := Open(path, JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := register(t, d, "github", "h")
	_ = d.Close()
	d, err = Open(path, JournalDelete, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := pragma(t, d, "journal_mode"); got != "delete" {
		t.Fatalf("journal_mode is %q", got)
	}
	if devices, err := d.DevicesOf(t.Context(), a.ID); err != nil || len(devices) != 1 {
		t.Fatalf("data lost in the conversion: %v %v", devices, err)
	}
}

func TestSwitchingModeWaitsForOtherConnectionsInsteadOfFailingAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	current, err := Open(path, JournalDelete, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	register(t, current, "github", "h")
	reader, err := current.sql.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ExecContext(t.Context(), `BEGIN DEFERRED`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reader.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM accounts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		d, err := Open(path, JournalWAL, time.Now)
		if err == nil {
			_ = d.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("the switch did not wait for the other connection: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_, _ = reader.ExecContext(t.Context(), `ROLLBACK`)
	_ = reader.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("the switch failed after the other reader left: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the switch never finished")
	}
	_ = current.Close()
}

func TestJournalSizeIsLimitedAndCheckpointTruncatesTheWAL(t *testing.T) {
	d, _ := open(t)
	if got := pragma(t, d, "journal_size_limit"); got != "4194304" {
		t.Fatalf("journal_size_limit is %q", got)
	}
	register(t, d, "github", "h")
	if err := d.CheckpointWAL(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := pragma(t, d, "journal_mode"); got != "wal" {
		t.Fatalf("%q", got)
	}
}
