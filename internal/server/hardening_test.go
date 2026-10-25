package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func openTestAdmin(t *testing.T) *Admin {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	a, err := OpenAdmin(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func TestAdminInviteForAnAccountRefusesAnUnknownAccount(t *testing.T) {
	a := openTestAdmin(t)
	if _, _, err := a.Invite(t.Context(), "nosuchaccount", time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an invite for an account that does not exist: %v", err)
	}
	acct, _, err := a.DB.RegisterProvider(t.Context(), "github", "h", store.NewDevice{Name: "a", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Invite(t.Context(), acct.ID, time.Hour); err != nil {
		t.Fatalf("an invite for an existing account: %v", err)
	}
}

func TestAdminInviteRefusesNeverExpiringAndOverlongCodes(t *testing.T) {
	a := openTestAdmin(t)
	for _, ttl := range []time.Duration{0, -time.Hour} {
		if _, _, err := a.Invite(t.Context(), "", ttl); err == nil {
			t.Errorf("ttl %v was accepted", ttl)
		}
	}
	max := a.Cfg.Auth.InviteTTL.Std()
	if _, _, err := a.Invite(t.Context(), "", max+time.Second); err == nil || !strings.Contains(err.Error(), "auth.invite_ttl") {
		t.Errorf("a code longer than the configured maximum was accepted: %v", err)
	}
	if _, _, err := a.Invite(t.Context(), "", max); err != nil {
		t.Errorf("the configured maximum itself was refused: %v", err)
	}
}

func TestBackupIsEncryptedToTheRecipientAndRestorable(t *testing.T) {
	a := openTestAdmin(t)
	const marker = "Backup-Marker-Device-Name"
	account, _, err := a.DB.RegisterProvider(t.Context(), "github", "h", store.NewDevice{Name: marker, SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := a.Backup(t.Context(), identity.Recipient(), &out); err != nil {
		t.Fatal(err)
	}

	encrypted := out.Bytes()
	if bytes.Contains(encrypted, []byte(marker)) || bytes.HasPrefix(encrypted, []byte("SQLite format 3")) {
		t.Fatal("the backup holds the database in clear")
	}
	if left, _ := filepath.Glob(filepath.Join(a.Cfg.DataDir, scratchPrefix+"*")); len(left) != 0 {
		t.Fatalf("a plaintext copy was left behind: %v", left)
	}

	other, _ := age.GenerateX25519Identity()
	if _, err := age.Decrypt(bytes.NewReader(encrypted), other); err == nil {
		t.Fatal("another key opened the backup")
	}
	reader, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.sqlite")
	plain, _ := io.ReadAll(reader)
	if err := os.WriteFile(restored, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(restored, store.JournalWAL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	devices, err := db.DevicesOf(t.Context(), account.ID)
	if err != nil || len(devices) != 1 || devices[0].Name != marker {
		t.Fatalf("restored database: %+v %v", devices, err)
	}
}

type failingWriter struct{ after int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("pipe closed")
	}
	w.after -= len(p)
	return len(p), nil
}

func TestBackupLeavesNoPlaintextScratchWhenItFailsOrIsCancelled(t *testing.T) {
	a := openTestAdmin(t)
	identity, _ := age.GenerateX25519Identity()
	left := func() []string {
		l, _ := filepath.Glob(filepath.Join(a.Cfg.DataDir, scratchPrefix+"*"))
		return l
	}
	if err := a.Backup(t.Context(), identity.Recipient(), &failingWriter{}); err == nil {
		t.Fatal("a closed output was not reported")
	}
	if l := left(); len(l) != 0 {
		t.Fatalf("scratch left after a failed write: %v", l)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.Backup(ctx, identity.Recipient(), io.Discard); err == nil {
		t.Fatal("a cancelled backup succeeded")
	}
	if l := left(); len(l) != 0 {
		t.Fatalf("scratch left after a cancel: %v", l)
	}
}

func TestStartingTheServerRemovesScratchLeftByAKilledBackup(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	stale := filepath.Join(cfg.DataDir, scratchPrefix+"123456")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "ostia.sqlite"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stale plaintext copy survived the start: %v", err)
	}
}

func TestSweepTruncatesTheWALSoDeletedPagesDoNotLinger(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules = config.Modules{Sync: true}
	srv, err := New(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	const marker = "Lingering-Device-Name-In-The-WAL"
	if _, _, err := srv.DB.RegisterProvider(t.Context(), "github", "h", store.NewDevice{Name: marker, SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10); err != nil {
		t.Fatal(err)
	}
	wal := filepath.Join(cfg.DataDir, "ostia.sqlite-wal")
	raw, err := os.ReadFile(wal)
	if err != nil || !bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("the test needs the marker in the WAL first: %v", err)
	}
	accounts, _ := srv.DB.Accounts(t.Context())
	if err := srv.Auth.DeleteAccount(t.Context(), accounts[0].ID); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(wal); !bytes.Contains(raw, []byte(marker)) {
		t.Fatal("expected the deleted row's old page to be in the WAL until a checkpoint")
	}
	srv.sweep(t.Context())
	if raw, _ := os.ReadFile(wal); bytes.Contains(raw, []byte(marker)) {
		t.Fatal("a deleted device name is still in the WAL after the sweep")
	}
	if info, err := os.Stat(wal); err != nil || info.Size() != 0 {
		t.Fatalf("the WAL was not truncated: %v %v", info, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(cfg.DataDir, "ostia.sqlite")); bytes.Contains(raw, []byte(marker)) {
		t.Fatal("a deleted device name is in the database file")
	}
}

func TestSweepDeletesRevokedDevicesPastTheirRetention(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules = config.Modules{Sync: true}
	cfg.Auth.RevokedDeviceRetention = config.Duration(48 * time.Hour)
	srv, err := New(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	acct, gone, err := srv.DB.RegisterProvider(t.Context(), "github", "h", store.NewDevice{Name: "a", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.DB.AddDevice(t.Context(), acct.ID, store.NewDevice{Name: "b", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10); err != nil {
		t.Fatal(err)
	}
	if err := srv.DB.RevokeInactiveDevice(t.Context(), acct.ID, gone.ID, math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	srv.sweep(t.Context())
	if _, err := srv.DB.Device(t.Context(), gone.ID); err != nil {
		t.Fatalf("deleted before its retention ran out: %v", err)
	}
	now = now.Add(48 * time.Hour)
	srv.sweep(t.Context())
	if _, err := srv.DB.Device(t.Context(), gone.ID); err == nil {
		t.Fatal("the revoked device row survived the sweep")
	}
}

func TestRoutesThatCarryMegabytesGetTheBulkDeadline(t *testing.T) {
	srv := everythingOn(t)
	got := srv.mux.BulkPatterns()
	slices.Sort(got)
	want := []string{
		"GET /v1/sync/blobs/{blobId}", "GET /v1/sync/manifest", "POST /v1/sync/rotate",
		"PUT /v1/shares/{id}/blob", "PUT /v1/sync/blobs/{blobId}", "PUT /v1/sync/manifest",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("bulk routes\n got %v\nwant %v", got, want)
	}
}

func TestStartupSweepRemovesOnlyScratchDirectoriesAndNeverOperatorFiles(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	target := t.TempDir()
	precious := filepath.Join(target, "precious")
	if err := os.WriteFile(precious, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := map[string]func(string) error{
		"backup-2026-10-21.age":     func(p string) error { return os.WriteFile(p, []byte("age"), 0o600) },
		"backup-2026-10-21":         func(p string) error { return os.Mkdir(p, 0o700) },
		scratchPrefix + "a-file":    func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) },
		scratchPrefix + "a-symlink": func(p string) error { return os.Symlink(target, p) },
	}
	for name, create := range keep {
		if err := create(filepath.Join(cfg.DataDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	gone := filepath.Join(cfg.DataDir, scratchPrefix+"real")
	if err := os.MkdirAll(filepath.Join(gone, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	for name := range keep {
		if _, err := os.Lstat(filepath.Join(cfg.DataDir, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
	if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the scratch directory survived: %v", err)
	}
	if kept, err := os.ReadFile(precious); err != nil || string(kept) != "keep" {
		t.Errorf("a symlink was followed into %s: %v", target, err)
	}
}

func TestSweepPurgesAccountsWithNoActiveDevice(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules = config.Modules{Sync: true}
	srv, err := New(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	device := store.NewDevice{Name: "a", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}
	acct, dev, err := srv.DB.RegisterProvider(t.Context(), "github", "h", device, 10)
	if err != nil {
		t.Fatal(err)
	}
	keep, _, err := srv.DB.RegisterProvider(t.Context(), "github", "other", device, 10)
	_ = keep
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.DB.RevokeInactiveDevice(t.Context(), acct.ID, dev.ID, math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	srv.sweep(t.Context())
	if abandoned, err := srv.DB.AbandonedAccounts(t.Context()); err != nil || len(abandoned) != 0 {
		t.Fatalf("the sweep must retry the purge of a departed account: %v %v", abandoned, err)
	}
}

func TestSweepRemovesSilentDevicesThenPurgesAccountsLeftEmpty(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules = config.Modules{Sync: true}
	cfg.Devices.InactiveAfter = config.Duration(90 * 24 * time.Hour)
	srv, err := New(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	device := store.NewDevice{Name: "a", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}
	lone, loneDev, err := srv.DB.RegisterProvider(t.Context(), "github", "lone", device, 10)
	if err != nil {
		t.Fatal(err)
	}
	pair, silent, err := srv.DB.RegisterProvider(t.Context(), "github", "pair", device, 10)
	if err != nil {
		t.Fatal(err)
	}
	var revoked []string
	srv.Auth.Hooks.DeviceRevoked = func(id string) { revoked = append(revoked, id) }
	now = now.Add(60 * 24 * time.Hour)
	awake, err := srv.DB.AddDevice(t.Context(), pair.ID, device, 10)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	srv.sweep(t.Context())
	if got, err := srv.DB.Device(t.Context(), silent.ID); err != nil || got.RevokedAt == 0 {
		t.Fatalf("a device silent past the limit must be revoked: %+v %v", got, err)
	}
	if got, err := srv.DB.Device(t.Context(), awake.ID); err != nil || got.RevokedAt != 0 {
		t.Fatalf("a recent device must stay: %+v %v", got, err)
	}
	if _, err := srv.DB.Device(t.Context(), loneDev.ID); err == nil {
		t.Fatal("an account left with no device must be purged in the same sweep")
	}
	if devices, _ := srv.DB.DevicesOf(t.Context(), pair.ID); len(devices) != 1 {
		t.Fatalf("the account that still has a device keeps it: %v", devices)
	}
	if len(revoked) != 2 {
		t.Fatalf("the revoke hook must run for each removed device: %v", revoked)
	}
	_ = lone
}

func TestSweepDoesNothingWhenTheInactivityLimitIsNotPositive(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules = config.Modules{Sync: true}
	srv, err := New(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	_, dev, err := srv.DB.RegisterProvider(t.Context(), "github", "h", store.NewDevice{Name: "a", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	srv.Auth.InactiveAfter = 0
	now = now.Add(1000 * 24 * time.Hour)
	if err := srv.Auth.RevokeInactive(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ := srv.DB.Device(t.Context(), dev.ID); got.RevokedAt != 0 {
		t.Fatal("with no limit configured the sweep must remove nothing")
	}
}
