package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func open(t *testing.T) (*DB, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), JournalWAL, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, c
}

func newDevice(name string) NewDevice {
	return NewDevice{Name: name, SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}
}

func register(t *testing.T, d *DB, provider, id string) (Account, Device) {
	t.Helper()
	a, dev, err := d.RegisterProvider(t.Context(), provider, id, newDevice("laptop"), 10)
	if err != nil {
		t.Fatal(err)
	}
	return a, dev
}

func revoke(t *testing.T, d *DB, accountID, deviceID string) {
	t.Helper()
	if err := d.RevokeInactiveDevice(t.Context(), accountID, deviceID, math.MaxInt64); err != nil {
		t.Fatal(err)
	}
}

func setKey(t *testing.T, d *DB, accountID string, ifMatch int64, label string) (version, keyVersion int64) {
	t.Helper()
	version, keyVersion, err := d.ReplaceKey(t.Context(), accountID, KeyReplacement{
		IfMatch: ifMatch, Manifest: []byte("manifest " + label), Passphrase: []byte("passphrase " + label), Recovery: []byte("recovery " + label),
		Retention: Retention{Versions: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	return version, keyVersion
}

func TestProviderSignInReusesTheAccount(t *testing.T) {
	d, _ := open(t)
	a1, d1 := register(t, d, "github", "hash1")
	a2, d2 := register(t, d, "github", "hash1")
	if a1.ID != a2.ID || d1.ID == d2.ID {
		t.Fatalf("same provider id must give one account and two devices: %v %v %v %v", a1.ID, a2.ID, d1.ID, d2.ID)
	}
	a3, _ := register(t, d, "github", "hash2")
	if a3.ID == a1.ID {
		t.Fatal("different provider id shares an account")
	}
	devices, _ := d.DevicesOf(t.Context(), a1.ID)
	if len(devices) != 2 {
		t.Fatalf("devices %d", len(devices))
	}
}

func TestDeviceLimit(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	for range 2 {
		if _, err := d.AddDevice(t.Context(), a.ID, newDevice("x"), 3); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.AddDevice(t.Context(), a.ID, newDevice("x"), 3); !errors.Is(err, ErrLimit) {
		t.Fatalf("want ErrLimit, got %v", err)
	}
}

func TestInviteIsSingleUseAndExpires(t *testing.T) {
	d, c := open(t)
	hash := ids.Hash("code-1")
	if _, err := d.CreateInvite(t.Context(), hash, "", time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), hash, newDevice("a"), 10); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), hash, newDevice("b"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invite reused: %v", err)
	}

	late := ids.Hash("code-3")
	_, _ = d.CreateInvite(t.Context(), late, "", time.Minute, "")
	c.t = c.t.Add(2 * time.Minute)
	if _, _, err := d.RegisterWithInvite(t.Context(), late, newDevice("c"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired invite accepted: %v", err)
	}
}

func TestAnAccountInviteAddsADeviceToThatAccountOnce(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	code := ids.Hash("bound")
	if _, err := d.CreateInvite(t.Context(), code, a.ID, time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), code, newDevice("x"), 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("want ErrLimit, got %v", err)
	}
	joined, dev, err := d.RegisterWithInvite(t.Context(), code, newDevice("x"), 5)
	if err != nil || joined.ID != a.ID || dev.AccountID != a.ID {
		t.Fatalf("the invite must add the device to its account and survive a failed registration: %v %v", joined.ID, err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), code, newDevice("y"), 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an account invite worked twice: %v", err)
	}
	if devices, _ := d.DevicesOf(t.Context(), a.ID); len(devices) != 2 {
		t.Fatalf("devices: %v", devices)
	}
	unused := ids.Hash("unused")
	_, _ = d.CreateInvite(t.Context(), unused, a.ID, time.Hour, "")
	if err := d.DeleteAccount(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), unused, newDevice("z"), 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an invite outlived its account: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	d, c := open(t)
	_, dev := register(t, d, "github", "h")
	hash := ids.Hash("tok")
	if _, err := d.CreateSession(t.Context(), hash, dev.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := d.SessionDevice(t.Context(), hash)
	if err != nil || got.ID != dev.ID {
		t.Fatalf("session device: %v %v", got.ID, err)
	}
	c.t = c.t.Add(2 * time.Hour)
	if _, err := d.SessionDevice(t.Context(), hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session accepted: %v", err)
	}
}

func TestRevokeRemovesSessionAndLabelButKeepsTheSyncKey(t *testing.T) {
	d, _ := open(t)
	a, dev := register(t, d, "github", "h")
	other, _ := d.AddDevice(t.Context(), a.ID, newDevice("phone"), 10)
	hash := ids.Hash("tok")
	_, _ = d.CreateSession(t.Context(), hash, other.ID, time.Hour)
	label, _ := d.LabelFor(t.Context(), other.ID, a.ID)
	setKey(t, d, a.ID, 0, "one")

	revoke(t, d, a.ID, other.ID)
	if _, err := d.SessionDevice(t.Context(), hash); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked device keeps its session")
	}
	if _, err := d.LabelOwner(t.Context(), label); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked device keeps its relay label")
	}
	if _, err := d.SyncKey(t.Context(), a.ID); err != nil {
		t.Fatalf("revoking a device removed the account's sync key: %v", err)
	}
	if devices, _ := d.DevicesOf(t.Context(), a.ID); len(devices) != 1 || devices[0].ID != dev.ID {
		t.Fatalf("devices after revoke: %v", devices)
	}
	if err := d.RevokeInactiveDevice(t.Context(), a.ID, other.ID, math.MaxInt64); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestManifestCompareAndSetAndHistory(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	if _, err := d.CurrentManifest(t.Context(), a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh account has a manifest: %v", err)
	}
	if _, err := d.PutManifest(t.Context(), a.ID, 0, []byte("one"), Retention{Versions: 3}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a manifest without a sync key was accepted: %v", err)
	}
	if v, _ := setKey(t, d, a.ID, 0, "one"); v != 1 {
		t.Fatalf("first manifest version %d", v)
	}
	if _, err := d.PutManifest(t.Context(), a.ID, 0, []byte("stale"), Retention{Versions: 3}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("stale put accepted: %v", err)
	} else if cur, ok := CurrentOf(err); !ok || cur != 1 {
		t.Fatalf("mismatch must report the current version: %d %v", cur, ok)
	}
	for i := range 4 {
		if _, err := d.PutManifest(t.Context(), a.ID, int64(1+i), []byte("next"), Retention{Versions: 3}); err != nil {
			t.Fatal(err)
		}
	}
	versions, _ := d.ManifestVersions(t.Context(), a.ID)
	if len(versions) != 3 || versions[0].Version != 5 || versions[2].Version != 3 || versions[0].KeyVersion != 1 {
		t.Fatalf("history not pruned to 3: %+v", versions)
	}
}

func TestReplaceKeyIsAtomicAndMovesTheKeyVersion(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	if _, err := d.SyncKey(t.Context(), a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh account has a sync key: %v", err)
	}
	if v, kv := setKey(t, d, a.ID, 0, "one"); v != 1 || kv != 1 {
		t.Fatalf("set up: version %d key version %d", v, kv)
	}
	if _, err := d.PutManifest(t.Context(), a.ID, 1, []byte("two"), Retention{Versions: 10}); err != nil {
		t.Fatal(err)
	}

	_, _, err := d.ReplaceKey(t.Context(), a.ID, KeyReplacement{IfMatch: 1, Manifest: []byte("m"), Passphrase: []byte("p"), Recovery: []byte("r")})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
	if k, _ := d.SyncKey(t.Context(), a.ID); k.Version != 1 || string(k.Passphrase) != "passphrase one" || string(k.Recovery) != "recovery one" {
		t.Fatalf("the key changed although the manifest swap failed: %+v", k)
	}

	if v, kv := setKey(t, d, a.ID, 2, "two"); v != 3 || kv != 2 {
		t.Fatalf("replace: version %d key version %d", v, kv)
	}
	k, _ := d.SyncKey(t.Context(), a.ID)
	if k.Version != 2 || string(k.Passphrase) != "passphrase two" || string(k.Recovery) != "recovery two" {
		t.Fatalf("key not replaced: %+v", k)
	}
	if m, _ := d.CurrentManifest(t.Context(), a.ID); m.KeyVersion != 2 || string(m.Blob) != "manifest two" {
		t.Fatalf("the new manifest must carry the new key version: %+v", m)
	}
	if m, _ := d.ManifestAt(t.Context(), a.ID, 2); m.KeyVersion != 1 {
		t.Fatalf("an older manifest keeps the key version it was sealed under: %+v", m)
	}
	if _, err := d.PutManifest(t.Context(), a.ID, 3, []byte("four"), Retention{Versions: 10}); err != nil {
		t.Fatal(err)
	}
	if m, _ := d.CurrentManifest(t.Context(), a.ID); m.KeyVersion != 2 {
		t.Fatalf("a manifest push keeps the current key version: %+v", m)
	}
}

func TestSyncBlobQuotaAndUnreferenced(t *testing.T) {
	d, c := open(t)
	a, _ := register(t, d, "github", "h")
	blob := func(id string, size int64) SyncBlob { return SyncBlob{ID: id, Size: size, Sum: ids.Hash(id)} }
	if err := d.AddSyncBlob(t.Context(), a.ID, blob("aaaaaaaaaaaaaaaa", 60), 100); err != nil {
		t.Fatal(err)
	}
	if err := d.AddSyncBlob(t.Context(), a.ID, blob("bbbbbbbbbbbbbbbb", 60), 100); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota not enforced: %v", err)
	}
	if err := d.AddSyncBlob(t.Context(), a.ID, blob("aaaaaaaaaaaaaaaa", 1), 100); err == nil {
		t.Fatal("blob id reused")
	}
	c.t = c.t.Add(2 * time.Hour)
	_ = d.AddSyncBlob(t.Context(), a.ID, blob("cccccccccccccccc", 10), 100)
	stale, err := d.CollectSyncBlobs(t.Context(), a.ID, 0, map[string]bool{"aaaaaaaaaaaaaaaa": true}, time.Hour)
	if err != nil || len(stale) != 0 {
		t.Fatalf("kept blob collected: %v %v", stale, err)
	}
	if _, err := d.CollectSyncBlobs(t.Context(), a.ID, 7, map[string]bool{}, time.Hour); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("a moved manifest must stop the collection: %v", err)
	}
	if touched, err := d.TouchSyncBlob(t.Context(), a.ID, "nosuchblobid0000"); err != nil || touched {
		t.Fatalf("touching a blob that is gone must say so: %v %v", touched, err)
	}
	if touched, err := d.TouchSyncBlob(t.Context(), a.ID, "aaaaaaaaaaaaaaaa"); err != nil || !touched {
		t.Fatalf("%v %v", touched, err)
	}
	if stale, _ := d.CollectSyncBlobs(t.Context(), a.ID, 0, map[string]bool{}, time.Hour); len(stale) != 0 {
		t.Fatalf("a re-uploaded blob is fresh again and must survive the grace period: %v", stale)
	}
	c.t = c.t.Add(2 * time.Hour)
	stale, err = d.CollectSyncBlobs(t.Context(), a.ID, 0, map[string]bool{}, time.Hour)
	if err != nil || len(stale) != 2 {
		t.Fatalf("grace period ignored: %v %v", stale, err)
	}
	if _, err := d.SyncBlob(t.Context(), a.ID, "aaaaaaaaaaaaaaaa"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("collected rows must be gone: %v", err)
	}
}

func TestTheDeployedSchemaIsKeptAndTheSeenTableIsDroppedByALaterMigration(t *testing.T) {
	if !strings.Contains(schemaV1, "CREATE TABLE device_seen") || !strings.Contains(schemaV2, "DROP TABLE device_seen") {
		t.Fatal("schemaV1 is deployed and must not change; schemaV2 drops the seen table")
	}
	d, _ := open(t)
	var n int
	if err := d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE name = 'device_seen'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("device_seen after migrating: %d %v", n, err)
	}
}

func TestRelayBytesRollOverEachMonth(t *testing.T) {
	d, c := open(t)
	a, dev := register(t, d, "github", "h")
	label, _ := d.LabelFor(t.Context(), dev.ID, a.ID)
	again, _ := d.LabelFor(t.Context(), dev.ID, a.ID)
	if label != again {
		t.Fatal("label must be stable per device")
	}
	_ = d.AddRelayBytes(t.Context(), label, d.Month(), 100)
	_ = d.AddRelayBytes(t.Context(), label, d.Month(), 50)
	if n, _ := d.AccountRelayBytes(t.Context(), a.ID, d.Month()); n != 150 {
		t.Fatalf("bytes %d", n)
	}
	c.t = c.t.AddDate(0, 1, 0)
	if n, _ := d.AccountRelayBytes(t.Context(), a.ID, d.Month()); n != 0 {
		t.Fatalf("new month starts with %d", n)
	}
	_ = d.AddRelayBytes(t.Context(), label, d.Month(), 7)
	if n, _ := d.AccountRelayBytes(t.Context(), a.ID, d.Month()); n != 7 {
		t.Fatalf("rollover lost: %d", n)
	}
}

func TestShareQuotaSweepAndTakedown(t *testing.T) {
	d, c := open(t)
	a, _ := register(t, d, "github", "h")
	quota := ShareQuota{MaxShares: 2, MaxBytes: 100}
	mk := func(id string, size int64, expires int64) Share {
		return Share{ID: id, AccountID: a.ID, Mode: "link", Size: size, ExpiresAt: expires, DeleteTokenHash: ids.Hash(id)}
	}
	soon := c.t.Add(time.Hour).UnixMilli()
	if err := d.CreateShare(t.Context(), mk("s1", 40, soon), quota); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateShare(t.Context(), mk("s2", 70, 0), quota); !errors.Is(err, ErrQuota) {
		t.Fatalf("byte quota: %v", err)
	}
	if err := d.CreateShare(t.Context(), mk("s2", 10, 0), quota); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateShare(t.Context(), mk("s3", 1, 0), quota); !errors.Is(err, ErrQuota) {
		t.Fatalf("count quota: %v", err)
	}
	if err := d.MarkUploaded(t.Context(), "s1"); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkUploaded(t.Context(), "s1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second upload: %v", err)
	}
	_ = d.MarkUploaded(t.Context(), "s2")
	_ = d.CountView(t.Context(), "s1")
	_ = d.CountView(t.Context(), "s1")
	if s, _ := d.Share(t.Context(), "s1"); s.Views != 2 {
		t.Fatalf("views %d", s.Views)
	}
	sweep, _ := d.SweepableShares(t.Context(), time.Hour)
	if len(sweep) != 0 {
		t.Fatalf("nothing is due: %v", sweep)
	}
	c.t = c.t.Add(2 * time.Hour)
	sweep, _ = d.SweepableShares(t.Context(), time.Hour)
	if len(sweep) != 1 || sweep[0].ID != "s1" {
		t.Fatalf("expired share not found: %v", sweep)
	}
	if err := d.TakeDown(t.Context(), "s2"); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.SharesOf(t.Context(), a.ID); len(list) != 1 {
		t.Fatalf("taken down share still listed: %d", len(list))
	}
}

func TestReportsSummary(t *testing.T) {
	d, _ := open(t)
	_ = d.AddReport(t.Context(), "gone", "abuse")
	_ = d.AddReport(t.Context(), "gone", "malware")
	sums, err := d.ReportSummaries(t.Context())
	if err != nil || len(sums) != 1 || sums[0].Reports != 2 || !sums[0].Removed {
		t.Fatalf("summaries: %+v %v", sums, err)
	}
}

func TestDeleteAccountCascades(t *testing.T) {
	d, _ := open(t)
	a, dev := register(t, d, "github", "h")
	setKey(t, d, a.ID, 0, "one")
	_, _ = d.LabelFor(t.Context(), dev.ID, a.ID)
	_ = d.CreateShare(t.Context(), Share{ID: "s1", AccountID: a.ID, Mode: "link", Size: 1, DeleteTokenHash: []byte("x")}, ShareQuota{})
	_ = d.MarkUploaded(t.Context(), "s1")
	_ = d.AddSyncBlob(t.Context(), a.ID, SyncBlob{ID: "aaaaaaaaaaaaaaaa", Size: 1, Sum: []byte("s")}, 0)

	keys, err := d.BlobKeysOf(t.Context(), a.ID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("blob keys: %v %v", keys, err)
	}
	if err := d.DeleteAccount(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	}
	for name, probe := range map[string]func() error{
		"device":   func() error { _, err := d.Device(t.Context(), dev.ID); return err },
		"manifest": func() error { _, err := d.CurrentManifest(t.Context(), a.ID); return err },
		"key":      func() error { _, err := d.SyncKey(t.Context(), a.ID); return err },
		"share":    func() error { _, err := d.Share(t.Context(), "s1"); return err },
	} {
		if err := probe(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s survived account deletion: %v", name, err)
		}
	}
}

func TestPushTicketsAreSingleUseExpiringAndBoundToAnAccount(t *testing.T) {
	d, c := open(t)
	a, _ := register(t, d, "github", "h")
	ticket := ids.Hash("ticket-1")
	if _, err := d.CreatePushTicket(t.Context(), ticket, a.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	h := PushHandle{Handle: "handle-1", Platform: "fcm", TokenSealed: []byte("t")}
	got, err := d.RegisterPushHandle(t.Context(), ticket, h, 5, 100)
	if err != nil || got.AccountID != a.ID {
		t.Fatalf("register: %+v %v", got, err)
	}
	if _, err := d.RegisterPushHandle(t.Context(), ticket, PushHandle{Handle: "handle-2", Platform: "fcm", TokenSealed: []byte("t")}, 5, 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a ticket worked twice: %v", err)
	}
	late := ids.Hash("ticket-2")
	_, _ = d.CreatePushTicket(t.Context(), late, a.ID, time.Minute)
	c.t = c.t.Add(2 * time.Minute)
	if _, err := d.RegisterPushHandle(t.Context(), late, PushHandle{Handle: "handle-3", Platform: "fcm", TokenSealed: []byte("t")}, 5, 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired ticket worked: %v", err)
	}
	if _, err := d.RegisterPushHandle(t.Context(), ids.Hash("never issued"), PushHandle{Handle: "handle-4", Platform: "fcm", TokenSealed: []byte("t")}, 5, 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown ticket worked: %v", err)
	}
}

func TestPushHandleLimitsAndCascade(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	b, _ := register(t, d, "github", "other")
	reg := func(account Account, name string, perAccount, total int) error {
		ticket := ids.Hash("t-" + name)
		if _, err := d.CreatePushTicket(t.Context(), ticket, account.ID, time.Minute); err != nil {
			t.Fatal(err)
		}
		_, err := d.RegisterPushHandle(t.Context(), ticket, PushHandle{Handle: name, Platform: "fcm", TokenSealed: []byte("t")}, perAccount, total)
		return err
	}
	if err := reg(a, "h1", 1, 3); err != nil {
		t.Fatal(err)
	}
	if err := reg(a, "h2", 1, 3); err != nil {
		t.Fatalf("at the per-account cap the oldest handle is replaced: %v", err)
	}
	if _, err := d.PushHandle(t.Context(), "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the oldest handle should have been evicted")
	}
	if _, err := d.PushHandle(t.Context(), "h2"); err != nil {
		t.Fatalf("the new handle should exist: %v", err)
	}
	if err := reg(b, "h3", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := reg(b, "h4", 5, 2); !errors.Is(err, ErrLimit) {
		t.Fatalf("total cap: %v", err)
	}
	if err := d.DeleteAccount(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PushHandle(t.Context(), "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("handles must go with their account")
	}
}

func TestOutstandingPushTicketsAreCapped(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	for i := range maxOutstandingTickets {
		if _, err := d.CreatePushTicket(t.Context(), ids.Hash(fmt.Sprint("t", i)), a.ID, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.CreatePushTicket(t.Context(), ids.Hash("one more"), a.ID, time.Minute); !errors.Is(err, ErrLimit) {
		t.Fatalf("%v", err)
	}
}

func TestManifestRetentionKeepsADailyCheckpointSoFloodingCannotEraseHistory(t *testing.T) {
	d, c := open(t)
	a, _ := register(t, d, "github", "h")
	keep := Retention{Versions: 3, CheckpointDays: 3}
	version, _ := setKey(t, d, a.ID, 0, "day1-setup")
	put := func(label string) {
		t.Helper()
		next, err := d.PutManifest(t.Context(), a.ID, version, []byte(label), keep)
		if err != nil {
			t.Fatal(err)
		}
		version = next
	}
	put("day1-a")
	put("day1-b")
	c.t = c.t.Add(24 * time.Hour)
	put("day2-a")
	put("day2-b")
	c.t = c.t.Add(24 * time.Hour)
	for range 40 {
		put("flood")
	}
	versions, _ := d.ManifestVersions(t.Context(), a.ID)
	if len(versions) != 3+2 {
		t.Fatalf("want the newest 3 plus a checkpoint for each of the two earlier days, got %d: %+v", len(versions), versions)
	}
	kept := map[string]bool{}
	for _, v := range versions {
		m, _ := d.ManifestAt(t.Context(), a.ID, v.Version)
		kept[string(m.Blob)] = true
	}
	if !kept["day1-b"] || !kept["day2-b"] || kept["day1-a"] || kept["day2-a"] {
		t.Fatalf("checkpoints must be the last version of each earlier day: %v", kept)
	}
	c.t = c.t.Add(5 * 24 * time.Hour)
	put("late")
	versions, _ = d.ManifestVersions(t.Context(), a.ID)
	if len(versions) != 3 {
		t.Fatalf("checkpoints older than the retention window must go: %d", len(versions))
	}
}

func TestPurgeDepartedDeletesSyncDataAndTheAccountUnlessSharesRemain(t *testing.T) {
	for _, withShare := range []bool{false, true} {
		d, _ := open(t)
		a, dev := register(t, d, "github", "h")
		if err := d.AddSyncBlob(t.Context(), a.ID, SyncBlob{ID: "blob1", Size: 3, Sum: make([]byte, 32)}, 100); err != nil {
			t.Fatal(err)
		}
		setKey(t, d, a.ID, 0, "one")
		if withShare {
			if err := d.CreateShare(t.Context(), Share{ID: ids.New(), AccountID: a.ID, Mode: "link", Size: 1, DeleteTokenHash: []byte("h")}, ShareQuota{MaxShares: 5, MaxBytes: 100}); err != nil {
				t.Fatal(err)
			}
		}
		revoke(t, d, a.ID, dev.ID)
		keys, deleted, err := d.PurgeDeparted(t.Context(), a.ID)
		if err != nil || len(keys) != 1 || keys[0] != SyncBlobKey(a.ID, "blob1") {
			t.Fatalf("share %v: keys %v err %v", withShare, keys, err)
		}
		if deleted == withShare {
			t.Fatalf("share %v: account deleted %v", withShare, deleted)
		}
		if _, err := d.SyncKey(t.Context(), a.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the sync key must be gone: %v", err)
		}
		if _, err := d.CurrentManifest(t.Context(), a.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("manifests must be gone: %v", err)
		}
	}
}

func TestUsedAccountInvitesStayUntilTheAccountIsGone(t *testing.T) {
	d, c := open(t)
	hash := ids.Hash("code-keep")
	if _, err := d.CreateInvite(t.Context(), hash, "", time.Hour, "KEEP-…-CODE"); err != nil {
		t.Fatal(err)
	}
	acct, _, err := d.RegisterWithInvite(t.Context(), hash, newDevice("a"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddDevice(t.Context(), acct.ID, newDevice("b"), 10); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(3 * 24 * time.Hour)
	if err := d.SweepInvites(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, used, err := d.AdminInvites(t.Context())
	if err != nil || len(used) != 1 || used[0].CreatedAccount != acct.ID || used[0].Hint != "KEEP-…-CODE" {
		t.Fatalf("the invite that created a live account must stay: %+v %v", used, err)
	}
	sums, _ := d.AccountSummaries(t.Context())
	if len(sums) != 1 || sums[0].InviteHint != "KEEP-…-CODE" || sums[0].Devices != 2 {
		t.Fatalf("%+v", sums)
	}
	if err := d.DeleteAccount(t.Context(), acct.ID); err != nil {
		t.Fatal(err)
	}
	if _, used, _ = d.AdminInvites(t.Context()); len(used) != 1 || used[0].CreatedAccount != "" {
		t.Fatalf("a deleted account must leave the invite without an account: %+v", used)
	}
	c.t = c.t.Add(2 * 24 * time.Hour)
	_ = d.SweepInvites(t.Context())
	if _, used, _ = d.AdminInvites(t.Context()); len(used) != 0 {
		t.Fatalf("an orphaned used invite is swept after a day: %+v", used)
	}
}

func TestSetupCodeClaimsTheFirstAdminOnce(t *testing.T) {
	d, _ := open(t)
	hash := ids.Hash("setup")
	if err := d.CreateSetupCode(t.Context(), hash, "AB12", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := d.SetupCodeValid(t.Context(), hash); err != nil {
		t.Fatal(err)
	}
	if hint, err := d.ClaimFirstAdmin(t.Context(), hash, 42, "octo", ids.Hash("tok"), time.Hour); err != nil || hint != "AB12" {
		t.Fatalf("%q %v", hint, err)
	}
	if err := d.SetupCodeValid(t.Context(), hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spent code still validates: %v", err)
	}
	if _, err := d.ClaimFirstAdmin(t.Context(), hash, 43, "other", ids.Hash("tok"), time.Hour); !errors.Is(err, ErrAdminExists) {
		t.Fatalf("a second admin was set up: %v", err)
	}
	if err := d.SignInAdmin(t.Context(), 43, "other", ids.Hash("tok"), time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if err := d.SignInAdmin(t.Context(), 42, "octo-renamed", ids.Hash("renamed"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if who, err := d.AdminSession(t.Context(), ids.Hash("renamed")); err != nil || who.GitHubID != 42 || who.Login != "octo-renamed" {
		t.Fatalf("%+v %v", who, err)
	}
	if who, err := d.AdminSession(t.Context(), ids.Hash("tok")); err != nil || who.GitHubID != 42 {
		t.Fatalf("claiming the first admin opens a session in the same transaction: %+v %v", who, err)
	}
	if _, err := d.AdminSession(t.Context(), ids.Hash("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused sign-in left a session: %v", err)
	}
}

func TestSetupCodeIsRefusedOnceUsedOrExpired(t *testing.T) {
	d, c := open(t)
	used := ids.Hash("used")
	_ = d.CreateSetupCode(t.Context(), used, "USED", 10*time.Minute)
	if _, err := d.ClaimFirstAdmin(t.Context(), used, 1, "a", ids.Hash("tok"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.ResetAdmins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimFirstAdmin(t.Context(), used, 2, "b", ids.Hash("tok"), time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spent code was accepted: %v", err)
	}
	late := ids.Hash("late")
	_ = d.CreateSetupCode(t.Context(), late, "LATE", 10*time.Minute)
	c.t = c.t.Add(11 * time.Minute)
	if _, err := d.ClaimFirstAdmin(t.Context(), late, 2, "b", ids.Hash("tok"), time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired code was accepted: %v", err)
	}
	if has, _ := d.HasAdmin(t.Context()); has {
		t.Fatal("a refused claim left an admin behind")
	}
}

func TestSetupCodeCannotBeIssuedWhileAnAdminExistsAndANewOneReplacesTheOld(t *testing.T) {
	d, _ := open(t)
	first, second := ids.Hash("first"), ids.Hash("second")
	_ = d.CreateSetupCode(t.Context(), first, "ONE", time.Minute)
	_ = d.CreateSetupCode(t.Context(), second, "TWO", time.Minute)
	if err := d.SetupCodeValid(t.Context(), first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an older code survived a new one: %v", err)
	}
	if _, err := d.ClaimFirstAdmin(t.Context(), second, 1, "a", ids.Hash("tok"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSetupCode(t.Context(), ids.Hash("third"), "THREE", time.Minute); !errors.Is(err, ErrAdminExists) {
		t.Fatalf("%v", err)
	}
}

func TestResetAdminsRemovesAdminsSessionsCodesAndPendingSignIns(t *testing.T) {
	d, _ := open(t)
	code := ids.Hash("code")
	_ = d.CreateSetupCode(t.Context(), code, "CODE", time.Hour)
	_, _ = d.ClaimFirstAdmin(t.Context(), code, 1, "a", ids.Hash("s"), time.Hour)
	_ = d.CreateSetupCode(t.Context(), ids.Hash("other"), "O", time.Hour)
	_ = d.CreateAdminOAuth(t.Context(), ids.Hash("state"), "verifier", nil, time.Hour)
	admins, sessions, err := d.ResetAdmins(t.Context())
	if err != nil || admins != 1 || sessions != 1 {
		t.Fatalf("%d %d %v", admins, sessions, err)
	}
	if has, _ := d.HasAdmin(t.Context()); has {
		t.Fatal("an admin survived the reset")
	}
	if _, err := d.AdminSession(t.Context(), ids.Hash("s")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if err := d.SetupCodeValid(t.Context(), ids.Hash("other")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, _, err := d.TakeAdminOAuth(t.Context(), ids.Hash("state")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestAdminOAuthStateIsSingleUseAndExpires(t *testing.T) {
	d, c := open(t)
	state := ids.Hash("state")
	if err := d.CreateAdminOAuth(t.Context(), state, "v1", ids.Hash("code"), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	verifier, code, err := d.TakeAdminOAuth(t.Context(), state)
	if err != nil || verifier != "v1" || !bytes.Equal(code, ids.Hash("code")) {
		t.Fatalf("%q %x %v", verifier, code, err)
	}
	if _, _, err := d.TakeAdminOAuth(t.Context(), state); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a state was taken twice: %v", err)
	}
	_ = d.CreateAdminOAuth(t.Context(), state, "v2", nil, 10*time.Minute)
	c.t = c.t.Add(11 * time.Minute)
	if _, _, err := d.TakeAdminOAuth(t.Context(), state); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired state was accepted: %v", err)
	}
	_ = d.CreateAdminOAuth(t.Context(), ids.Hash("old"), "v3", nil, time.Minute)
	c.t = c.t.Add(time.Hour)
	if err := d.SweepAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM admin_oauth`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d %v", left, err)
	}
}

func newAdmin(t *testing.T, d *DB, id int64, token string) {
	t.Helper()
	code := ids.Hash(fmt.Sprint("setup", id))
	if err := d.CreateSetupCode(t.Context(), code, "CODE", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimFirstAdmin(t.Context(), code, id, "admin", ids.Hash(token), time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestAdminSessionsExpireAndAreSwept(t *testing.T) {
	d, c := open(t)
	newAdmin(t, d, 7, "session")
	token := ids.Hash("session")
	if who, err := d.AdminSession(t.Context(), token); err != nil || who.GitHubID != 7 || who.Login != "admin" {
		t.Fatalf("%+v %v", who, err)
	}
	c.t = c.t.Add(2 * time.Hour)
	if _, err := d.AdminSession(t.Context(), token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired session was accepted: %v", err)
	}
	if err := d.SweepAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionOfARemovedAdminStopsWorkingAtOnce(t *testing.T) {
	d, _ := open(t)
	newAdmin(t, d, 7, "session")
	if _, err := d.sql.ExecContext(t.Context(), `DELETE FROM admins`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AdminSession(t.Context(), ids.Hash("session")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a session outlived its admin: %v", err)
	}
}

func TestCountedAuditRowsMergeWithinAMinute(t *testing.T) {
	d, c := open(t)
	for range 5 {
		if err := d.CountAudit(t.Context(), "anonymous", "refused", "state-mismatch"); err != nil {
			t.Fatal(err)
		}
	}
	_ = d.CountAudit(t.Context(), "anonymous", "refused", "state-unknown")
	got, _ := d.Audit(t.Context(), 10)
	if len(got) != 2 || got[1].Target != "state-mismatch" || got[1].Count != 5 || got[0].Count != 1 {
		t.Fatalf("%+v", got)
	}
	c.t = c.t.Add(2 * time.Minute)
	_ = d.CountAudit(t.Context(), "anonymous", "refused", "state-mismatch")
	if got, _ = d.Audit(t.Context(), 10); len(got) != 3 || got[0].Count != 1 {
		t.Fatalf("a new minute starts a new row: %+v", got)
	}
}

func TestAuditListsTheNewestFirst(t *testing.T) {
	d, c := open(t)
	for _, action := range []string{"login", "invite.create", "logout"} {
		c.t = c.t.Add(time.Second)
		if err := d.AddAudit(t.Context(), "admin", action, "x"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := d.Audit(t.Context(), 2)
	if err != nil || len(got) != 2 || got[0].Action != "logout" || got[1].Action != "invite.create" || got[0].At <= got[1].At {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestDeleteAdminSessionsEndsEveryOne(t *testing.T) {
	d, _ := open(t)
	newAdmin(t, d, 7, "a")
	for _, name := range []string{"b", "c"} {
		if err := d.SignInAdmin(t.Context(), 7, "admin", ids.Hash(name), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	n, err := d.DeleteAdminSessions(t.Context())
	if err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := d.AdminSession(t.Context(), ids.Hash("a")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestPurgeDepartedDoesNothingWhileADeviceIsActive(t *testing.T) {
	d, _ := open(t)
	a, first := register(t, d, "github", "h")
	setKey(t, d, a.ID, 0, "one")
	revoke(t, d, a.ID, first.ID)
	if _, err := d.AddDevice(t.Context(), a.ID, newDevice("joined while the last one left"), 10); err != nil {
		t.Fatal(err)
	}
	keys, deleted, err := d.PurgeDeparted(t.Context(), a.ID)
	if err != nil || len(keys) != 0 || deleted {
		t.Fatalf("the account has a device again: %v %v %v", keys, deleted, err)
	}
	if _, err := d.SyncKey(t.Context(), a.ID); err != nil {
		t.Fatalf("a joined device lost the sync key: %v", err)
	}
}

func TestAbandonedAccountsAreFoundAndOnlyLiveSharesKeepThemAlive(t *testing.T) {
	d, c := open(t)
	share := func(a Account, expiresIn time.Duration) string {
		id := ids.New()
		expires := int64(0)
		if expiresIn != 0 {
			expires = c.t.Add(expiresIn).UnixMilli()
		}
		if err := d.CreateShare(t.Context(), Share{ID: id, AccountID: a.ID, Mode: "link", Size: 1, ExpiresAt: expires, DeleteTokenHash: []byte("h")}, ShareQuota{MaxShares: 5, MaxBytes: 100}); err != nil {
			t.Fatal(err)
		}
		if err := d.MarkUploaded(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	active, _ := register(t, d, "github", "active")
	removedOnly, rd := register(t, d, "github", "removed")
	expiredOnly, ed := register(t, d, "github", "expired")
	live, ld := register(t, d, "github", "live")
	if err := d.TakeDown(t.Context(), share(removedOnly, 0)); err != nil {
		t.Fatal(err)
	}
	expiredID := share(expiredOnly, time.Minute)
	share(live, 0)
	for acct, dev := range map[string]Device{removedOnly.ID: rd, expiredOnly.ID: ed, live.ID: ld} {
		revoke(t, d, acct, dev.ID)
	}
	c.t = c.t.Add(time.Hour)
	abandoned, err := d.AbandonedAccounts(t.Context())
	if err != nil || len(abandoned) != 3 || slices.Contains(abandoned, active.ID) {
		t.Fatalf("abandoned: %v %v", abandoned, err)
	}
	if _, gone, err := d.PurgeDeparted(t.Context(), removedOnly.ID); err != nil || !gone {
		t.Fatalf("an account whose shares are all removed goes: %v %v", gone, err)
	}
	keys, gone, err := d.PurgeDeparted(t.Context(), expiredOnly.ID)
	if err != nil || !gone || !slices.Contains(keys, ShareBlobKey(expiredID)) {
		t.Fatalf("expired shares are not live, and their blobs are returned: %v %v %v", gone, keys, err)
	}
	if _, gone, err := d.PurgeDeparted(t.Context(), live.ID); err != nil || gone {
		t.Fatalf("a live share keeps its account: %v %v", gone, err)
	}
}

func TestADatabaseAtSchemaV1UpgradesToTheLatest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		schemaV1,
		`PRAGMA user_version = 1`,
		`INSERT INTO accounts (id, provider, provider_id_hash, created_at) VALUES ('acct', 'github', 'h', 1)`,
		`INSERT INTO devices (id, account_id, name, sign_pub, box_pub, created_at, last_seen) VALUES ('d1', 'acct', 'a', x'00', x'00', 1, 1), ('d2', 'acct', 'b', x'00', x'00', 1, 1)`,
		`INSERT INTO device_seen (viewer_device_id, device_id) VALUES ('d1', 'd2')`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, err := Open(path, JournalWAL, c.now)
	if err != nil {
		t.Fatalf("a deployed V1 database must open: %v", err)
	}
	defer d.Close()
	var version, seen, devices, backfilled int
	_ = d.sql.QueryRowContext(t.Context(), `PRAGMA user_version`).Scan(&version)
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE name = 'device_seen'`).Scan(&seen)
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM devices`).Scan(&devices)
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM devices WHERE last_seen_at = ?`, c.t.UnixMilli()).Scan(&backfilled)
	if version != len(migrations) || seen != 0 || devices != 2 {
		t.Fatalf("version %d, device_seen tables %d, devices %d", version, seen, devices)
	}
	if backfilled != 2 {
		t.Fatalf("existing devices must start their inactivity clock at the upgrade, not at their old last seen: %d of 2", backfilled)
	}
}

func TestAHeartbeatBetweenTheListAndTheRevokeSavesTheDevice(t *testing.T) {
	d, c := open(t)
	_, dev := register(t, d, "github", "h")
	limit := 90 * 24 * time.Hour
	c.t = c.t.Add(limit + 24*time.Hour)
	silent, err := d.InactiveDevices(t.Context(), limit)
	if err != nil || len(silent) != 1 {
		t.Fatalf("%v %v", silent, err)
	}
	cutoff := c.t.Add(-limit).UnixMilli()
	if err := d.TouchDevice(t.Context(), dev.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeInactiveDevice(t.Context(), silent[0].AccountID, silent[0].ID, cutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a device that checked in after the list must be skipped: %v", err)
	}
	if got, _ := d.Device(t.Context(), dev.ID); got.RevokedAt != 0 {
		t.Fatal("the device was revoked after it checked in")
	}
	c.t = c.t.Add(limit + 24*time.Hour)
	if err := d.RevokeInactiveDevice(t.Context(), dev.AccountID, dev.ID, c.t.Add(-limit).UnixMilli()); err != nil {
		t.Fatalf("a device that stayed silent is revoked: %v", err)
	}
}

func TestSchemaV3KeepsOneKeyPerAccountAndDropsDeviceTrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		schemaV1,
		strings.ReplaceAll(schemaV2, "{now}", "1"),
		`PRAGMA user_version = 2`,
		`INSERT INTO accounts (id, provider, provider_id_hash, created_at) VALUES ('full', 'github', 'h1', 1), ('half', 'github', 'h2', 1)`,
		`INSERT INTO devices (id, account_id, name, sign_pub, box_pub, created_at, last_seen_at) VALUES ('d1', 'full', 'a', x'00', x'00', 1, 1), ('d2', 'half', 'b', x'00', x'00', 1, 1)`,
		`INSERT INTO sessions (token_hash, device_id, expires_at, elevated_until) VALUES (x'01', 'd1', 9999999999999, 5)`,
		`INSERT INTO approvals (id, account_id, requester_device_id, requester_token_hash, created_at, expires_at) VALUES ('ap', 'full', 'd1', x'01', 1, 2)`,
		`INSERT INTO invites (code_hash, account_id, created_at, expires_at, hint) VALUES (x'aa', NULL, 1, 9999999999999, 'ADMIN'), (x'bb', 'full', 1, 9999999999999, '')`,
		`INSERT INTO key_wraps (account_id, slot, blob, updated_at) VALUES ('full', 'passphrase', x'70', 10), ('full', 'recovery', x'72', 20), ('full', 'device:d1', x'64', 30), ('half', 'passphrase', x'70', 10)`,
		`INSERT INTO sync_manifests (account_id, version, blob, updated_at) VALUES ('full', 1, x'6d', 1), ('half', 1, x'6d', 1)`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	d, err := Open(path, JournalWAL, c.now)
	if err != nil {
		t.Fatalf("a deployed V2 database must open: %v", err)
	}
	defer d.Close()
	k, err := d.SyncKey(t.Context(), "full")
	if err != nil || k.Version != 1 || string(k.Passphrase) != "p" || string(k.Recovery) != "r" || k.UpdatedAt != 20 {
		t.Fatalf("the passphrase and recovery wraps must become key version 1: %+v %v", k, err)
	}
	if m, err := d.CurrentManifest(t.Context(), "full"); err != nil || m.KeyVersion != 1 {
		t.Fatalf("an existing manifest belongs to key version 1: %+v %v", m, err)
	}
	if _, err := d.SyncKey(t.Context(), "half"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an account without both wraps has no key: %v", err)
	}
	if _, err := d.CurrentManifest(t.Context(), "half"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a manifest without a key must go so the account can be set up again: %v", err)
	}
	var tables, invites, adminInvites int
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE name IN ('approvals', 'key_wraps')`).Scan(&tables)
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM invites`).Scan(&invites)
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM invites WHERE hint = 'ADMIN'`).Scan(&adminInvites)
	var accountInvites int
	_ = d.sql.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM invites WHERE account_id IS NOT NULL`).Scan(&accountInvites)
	if tables != 0 || invites != 1 || adminInvites != 1 || accountInvites != 0 {
		t.Fatalf("approvals and wrap tables %d, invites %d (admin %d)", tables, invites, adminInvites)
	}
	if dev, err := d.SessionDevice(t.Context(), []byte{1}); err != nil || dev.ID != "d1" {
		t.Fatalf("sessions survive the migration: %+v %v", dev, err)
	}
}
