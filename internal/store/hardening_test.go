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
	d, err := Open(path, time.Now)
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
	d, err := Open(path, time.Now)
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
		if _, err := d.CreateInvite(t.Context(), ids.Hash("code"), "", ttl, false); !errors.Is(err, ErrInvalidTTL) {
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
	copyDB, err := Open(out, time.Now)
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
