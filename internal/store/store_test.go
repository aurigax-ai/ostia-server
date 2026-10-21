package store

import (
	"errors"
	"fmt"
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
	if _, err := d.CreateInvite(t.Context(), hash, "", time.Hour, false); err != nil {
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
	if _, err := d.CreateInvite(t.Context(), bound, acct.ID, time.Minute, false); err != nil {
		t.Fatal(err)
	}
	a2, _, err := d.RegisterWithInvite(t.Context(), bound, newDevice("b"), 10)
	if err != nil || a2.ID != acct.ID {
		t.Fatalf("bound invite must join the account: %v %v", a2.ID, err)
	}

	late := ids.Hash("code-3")
	_, _ = d.CreateInvite(t.Context(), late, "", time.Minute, false)
	c.t = c.t.Add(2 * time.Minute)
	if _, _, err := d.RegisterWithInvite(t.Context(), late, newDevice("c"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired invite accepted: %v", err)
	}
}

func TestInviteStaysUnusedWhenDeviceLimitHit(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	code := ids.Hash("bound")
	_, _ = d.CreateInvite(t.Context(), code, a.ID, time.Hour, false)
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
	v, err := d.PutManifest(t.Context(), a.ID, 0, []byte("one"), Retention{Versions: 3})
	if err != nil || v != 1 {
		t.Fatalf("first put: %d %v", v, err)
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
	if len(versions) != 3 || versions[0].Version != 5 || versions[2].Version != 3 {
		t.Fatalf("history not pruned to 3: %+v", versions)
	}
}

func TestRotateIsAtomic(t *testing.T) {
	d, _ := open(t)
	a, dev := register(t, d, "github", "h")
	_, _ = d.PutManifest(t.Context(), a.ID, 0, []byte("m1"), Retention{Versions: 10})
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
		IfMatch: 1, Manifest: []byte("m2"), Retention: Retention{Versions: 10},
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
	_, _ = d.PutManifest(t.Context(), a.ID, 0, []byte("m"), Retention{Versions: 10})
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

func TestElevationLivesOnTheSessionAndApprovalNeedsAnotherDevice(t *testing.T) {
	d, c := open(t)
	a, first := register(t, d, "github", "h")
	second, _ := d.AddDevice(t.Context(), a.ID, newDevice("phone"), 10)
	token := ids.Hash("tok-1")
	_, _ = d.CreateSession(t.Context(), token, first.ID, time.Hour)
	sess, err := d.LookupSession(t.Context(), token)
	if err != nil || sess.ElevatedUntil != 0 {
		t.Fatalf("fresh session: %+v %v", sess, err)
	}
	approval, err := d.CreateApproval(t.Context(), a.ID, first.ID, token, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if pending, _ := d.PendingApprovals(t.Context(), a.ID, first.ID); len(pending) != 0 {
		t.Fatal("the requester must not see its own request as something to approve")
	}
	pending, _ := d.PendingApprovals(t.Context(), a.ID, second.ID)
	if len(pending) != 1 || pending[0].RequesterName != "laptop" {
		t.Fatalf("pending: %+v", pending)
	}
	until := c.t.Add(5 * time.Minute).UnixMilli()
	if err := d.Approve(t.Context(), approval.ID, a.ID, first.ID, until, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("self approval: %v", err)
	}
	other, _ := register(t, d, "github", "stranger")
	if err := d.Approve(t.Context(), approval.ID, other.ID, second.ID, until, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approval across accounts: %v", err)
	}
	if err := d.Approve(t.Context(), approval.ID, a.ID, second.ID, until, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.Approve(t.Context(), approval.ID, a.ID, second.ID, until, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approving twice: %v", err)
	}
	sess, _ = d.LookupSession(t.Context(), token)
	if sess.ElevatedUntil != until {
		t.Fatalf("elevation not applied: %d", sess.ElevatedUntil)
	}
	got, err := d.ApprovalOf(t.Context(), approval.ID, token)
	if err != nil || got.ApprovedAt == 0 {
		t.Fatalf("requester view: %+v %v", got, err)
	}
	if _, err := d.ApprovalOf(t.Context(), approval.ID, ids.Hash("other session")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another session read the approval: %v", err)
	}

	late, _ := d.CreateApproval(t.Context(), a.ID, first.ID, token, time.Minute)
	c.t = c.t.Add(2 * time.Minute)
	if err := d.Approve(t.Context(), late.ID, a.ID, second.ID, until, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired approval: %v", err)
	}
}

func TestManifestRetentionKeepsADailyCheckpointSoFloodingCannotEraseHistory(t *testing.T) {
	d, c := open(t)
	a, _ := register(t, d, "github", "h")
	keep := Retention{Versions: 3, CheckpointDays: 3}
	version := int64(0)
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

func TestUnelevatedInviteIsRefusedOnceTheAccountHasTwoDevices(t *testing.T) {
	d, _ := open(t)
	a, _ := register(t, d, "github", "h")
	plain, elevated := ids.Hash("plain"), ids.Hash("elevated")
	_, _ = d.CreateInvite(t.Context(), plain, a.ID, time.Hour, false)
	_, _ = d.CreateInvite(t.Context(), elevated, a.ID, time.Hour, true)
	if n, _ := d.LiveInvites(t.Context(), a.ID); n != 2 {
		t.Fatalf("live invites %d", n)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), plain, newDevice("b"), 10); err != nil {
		t.Fatalf("the second device of an account needs no elevation: %v", err)
	}
	other, _ := d.AddDevice(t.Context(), a.ID, newDevice("c"), 10)
	_ = other
	again := ids.Hash("again")
	_, _ = d.CreateInvite(t.Context(), again, a.ID, time.Hour, false)
	if _, _, err := d.RegisterWithInvite(t.Context(), again, newDevice("d"), 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an invite minted without elevation must not work once there are two devices: %v", err)
	}
	if _, _, err := d.RegisterWithInvite(t.Context(), elevated, newDevice("e"), 10); err != nil {
		t.Fatalf("an elevated invite keeps working: %v", err)
	}
}

func TestUnseenDevicesAndEstablishedCounts(t *testing.T) {
	d, c := open(t)
	a, first := register(t, d, "github", "h")
	c.t = c.t.Add(time.Hour)
	second, _ := d.AddDevice(t.Context(), a.ID, newDevice("phone"), 10)
	unseen, err := d.UnseenDevices(t.Context(), first)
	if err != nil || !unseen[second.ID] || unseen[first.ID] {
		t.Fatalf("%v %v", unseen, err)
	}
	if got, _ := d.UnseenDevices(t.Context(), second); len(got) != 0 {
		t.Fatalf("a device is not told about devices that were there before it: %v", got)
	}
	_ = d.MarkSeen(t.Context(), first.ID, second.ID)
	if got, _ := d.UnseenDevices(t.Context(), first); len(got) != 0 {
		t.Fatalf("seen devices stay flagged: %v", got)
	}
	if n, _ := d.OlderActiveDevices(t.Context(), second); n != 1 {
		t.Fatalf("older devices %d", n)
	}
	if n, _ := d.OlderActiveDevices(t.Context(), first); n != 0 {
		t.Fatalf("the oldest device has nothing older: %d", n)
	}
}
