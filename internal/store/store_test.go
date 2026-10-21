package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/ids"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func open(t *testing.T) (*DB, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), c.now)
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
	if _, err := d.CreateInvite(t.Context(), hash, "", time.Hour); err != nil {
		t.Fatal(err)
	}
	acct, _, err := d.RegisterWithInvite(t.Context(), hash, newDevice("a"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), hash, newDevice("b"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invite reused: %v", err)
	}

	bound := ids.Hash("code-2")
	if _, err := d.CreateInvite(t.Context(), bound, acct.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	a2, _, err := d.RegisterWithInvite(t.Context(), bound, newDevice("b"), 10)
	if err != nil || a2.ID != acct.ID {
		t.Fatalf("bound invite must join the account: %v %v", a2.ID, err)
	}

	late := ids.Hash("code-3")
	_, _ = d.CreateInvite(t.Context(), late, "", time.Minute)
	c.t = c.t.Add(2 * time.Minute)
	if _, _, err := d.RegisterWithInvite(t.Context(), late, newDevice("c"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired invite accepted: %v", err)
	}
}

func TestInviteStaysUnusedWhenDeviceLimitHit(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	code := ids.Hash("bound")
	_, _ = d.CreateInvite(t.Context(), code, a.ID, time.Hour)
	if _, _, err := d.RegisterWithInvite(t.Context(), code, newDevice("x"), 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("want ErrLimit, got %v", err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), code, newDevice("x"), 5); err != nil {
		t.Fatalf("invite was consumed by a failed registration: %v", err)
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

func TestRevokeDeviceRemovesSessionLabelAndWrap(t *testing.T) {
	d, _ := open(t)
	a, dev := register(t, d, "github", "h")
	other, _ := d.AddDevice(t.Context(), a.ID, newDevice("phone"), 10)
	hash := ids.Hash("tok")
	_, _ = d.CreateSession(t.Context(), hash, other.ID, time.Hour)
	label, _ := d.LabelFor(t.Context(), other.ID, a.ID)
	_ = d.PutWrap(t.Context(), a.ID, DeviceSlot(other.ID), []byte("wrap"))
	_ = d.PutWrap(t.Context(), a.ID, "passphrase", []byte("p"))

	gotLabel, err := d.RevokeDevice(t.Context(), a.ID, other.ID)
	if err != nil || gotLabel != label {
		t.Fatalf("revoke: %q %v", gotLabel, err)
	}
	if _, err := d.SessionDevice(t.Context(), hash); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked device keeps its session")
	}
	if _, err := d.LabelOwner(t.Context(), label); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked device keeps its relay label")
	}
	if _, err := d.Wrap(t.Context(), a.ID, DeviceSlot(other.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked device keeps its wrap")
	}
	if _, err := d.Wrap(t.Context(), a.ID, "passphrase"); err != nil {
		t.Fatalf("revoking a device removed another wrap: %v", err)
	}
	if devices, _ := d.DevicesOf(t.Context(), a.ID); len(devices) != 1 || devices[0].ID != dev.ID {
		t.Fatalf("devices after revoke: %v", devices)
	}
	if _, err := d.RevokeDevice(t.Context(), a.ID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestManifestCompareAndSetAndHistory(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	if _, err := d.CurrentManifest(t.Context(), a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh account has a manifest: %v", err)
	}
	v, err := d.PutManifest(t.Context(), a.ID, 0, []byte("one"), 3)
	if err != nil || v != 1 {
		t.Fatalf("first put: %d %v", v, err)
	}
	if _, err := d.PutManifest(t.Context(), a.ID, 0, []byte("stale"), 3); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("stale put accepted: %v", err)
	} else if cur, ok := CurrentOf(err); !ok || cur != 1 {
		t.Fatalf("mismatch must report the current version: %d %v", cur, ok)
	}
	for i := range 4 {
		if _, err := d.PutManifest(t.Context(), a.ID, int64(1+i), []byte("next"), 3); err != nil {
			t.Fatal(err)
		}
	}
	versions, _ := d.ManifestVersions(t.Context(), a.ID)
	if len(versions) != 3 || versions[0].Version != 5 || versions[2].Version != 3 {
		t.Fatalf("history not pruned to 3: %+v", versions)
	}
}

func TestRotateIsAtomic(t *testing.T) {
	d, _ := open(t)
	a, dev := register(t, d, "github", "h")
	_, _ = d.PutManifest(t.Context(), a.ID, 0, []byte("m1"), 10)
	_ = d.PutWrap(t.Context(), a.ID, "passphrase", []byte("old"))
	_ = d.PutWrap(t.Context(), a.ID, DeviceSlot(dev.ID), []byte("olddev"))

	_, err := d.Rotate(t.Context(), a.ID, Rotation{IfMatch: 7, Manifest: []byte("m2"), Wraps: map[string][]byte{"passphrase": []byte("new")}})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
	if w, _ := d.Wrap(t.Context(), a.ID, "passphrase"); string(w.Blob) != "old" {
		t.Fatal("wrap changed although the manifest swap failed")
	}

	v, err := d.Rotate(t.Context(), a.ID, Rotation{
		IfMatch: 1, Manifest: []byte("m2"), History: 10,
		Wraps:       map[string][]byte{"passphrase": []byte("new")},
		DeleteSlots: []string{DeviceSlot(dev.ID)},
	})
	if err != nil || v != 2 {
		t.Fatalf("rotate: %d %v", v, err)
	}
	if w, _ := d.Wrap(t.Context(), a.ID, "passphrase"); string(w.Blob) != "new" {
		t.Fatal("wrap not replaced")
	}
	if _, err := d.Wrap(t.Context(), a.ID, DeviceSlot(dev.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatal("device wrap not removed")
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
	stale, _ := d.UnreferencedSyncBlobs(t.Context(), a.ID, map[string]bool{}, time.Hour)
	if len(stale) != 1 || stale[0] != "aaaaaaaaaaaaaaaa" {
		t.Fatalf("grace period ignored: %v", stale)
	}
	stale, _ = d.UnreferencedSyncBlobs(t.Context(), a.ID, map[string]bool{"aaaaaaaaaaaaaaaa": true}, time.Hour)
	if len(stale) != 0 {
		t.Fatalf("kept blob listed: %v", stale)
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
	_, _ = d.PutManifest(t.Context(), a.ID, 0, []byte("m"), 10)
	_ = d.PutWrap(t.Context(), a.ID, "passphrase", []byte("w"))
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
		"wrap":     func() error { _, err := d.Wrap(t.Context(), a.ID, "passphrase"); return err },
		"share":    func() error { _, err := d.Share(t.Context(), "s1"); return err },
	} {
		if err := probe(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s survived account deletion: %v", name, err)
		}
	}
}

func TestPushHandleLimit(t *testing.T) {
	d, _ := open(t)
	h := PushHandle{Handle: "h1", Platform: "fcm", TokenSealed: []byte("t")}
	if err := d.AddPushHandle(t.Context(), h, 1); err != nil {
		t.Fatal(err)
	}
	h.Handle = "h2"
	if err := d.AddPushHandle(t.Context(), h, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	if err := d.DeletePushHandle(t.Context(), "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PushHandle(t.Context(), "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("handle not deleted")
	}
}
