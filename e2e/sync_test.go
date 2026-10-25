package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

type syncFixture struct {
	env *env
	a   *testkit.SyncDevice
}

const (
	passphrase  = "correct horse"
	recoveryKey = "RECOVERYKEYRECOVERYKE"
)

func newSyncFixture(t *testing.T, extra string) *syncFixture {
	t.Helper()
	e := newGitHubEnv(t, extra)
	a := testkit.NewSyncDevice(e.githubUser(t, "laptop"))
	a.Create(t, passphrase, recoveryKey)
	return &syncFixture{env: e, a: a}
}

func (f *syncFixture) addDevice(t *testing.T, name string) *testkit.SyncDevice {
	t.Helper()
	d := testkit.NewSyncDevice(f.env.device(t, f.a.API, name))
	if err := d.Unlock(t, "passphrase", passphrase); err != nil {
		t.Fatal(err)
	}
	return d
}

func settings(pairs ...string) testkit.Files {
	keys := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		keys[pairs[i]] = pairs[i+1]
	}
	return testkit.Files{"settings.json": keys}
}

func TestTwoDevicesConvergeWithPerKeyMerge(t *testing.T) {
	f := newSyncFixture(t, "")
	a := f.a
	b := f.addDevice(t, "desktop")

	first, err := a.Sync(t, settings("theme", "dark", "font", "14"))
	if err != nil || first.Counter != 2 {
		t.Fatalf("first sync: %+v %v", first, err)
	}
	got, err := b.Pull(t)
	if err != nil || !testkit.Equal(got, settings("theme", "dark", "font", "14")) {
		t.Fatalf("B did not receive A's data: %v %v", got, err)
	}

	if _, err := a.Sync(t, settings("theme", "dark", "font", "16")); err != nil {
		t.Fatal(err)
	}
	res, err := b.Sync(t, settings("theme", "light", "font", "14"))
	if err != nil || len(res.Conflicts) != 0 {
		t.Fatalf("B's sync: %+v %v", res, err)
	}
	want := settings("theme", "light", "font", "16")
	if !testkit.Equal(res.Merged, want) {
		t.Fatalf("different keys changed on both sides must both survive: %v", res.Merged)
	}
	final, err := a.Sync(t, settings("theme", "dark", "font", "16"))
	if err != nil || !testkit.Equal(final.Merged, want) {
		t.Fatalf("A did not converge: %v %v", final.Merged, err)
	}
}

func TestSameKeyChangedOnBothSidesIsReportedNotOverwritten(t *testing.T) {
	f := newSyncFixture(t, "")
	b := f.addDevice(t, "desktop")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Pull(t); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Sync(t, settings("theme", "solarized")); err != nil {
		t.Fatal(err)
	}
	res, err := b.Sync(t, settings("theme", "light"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0].Key != "theme" || *res.Conflicts[0].Local != "light" || *res.Conflicts[0].Remote != "solarized" {
		t.Fatalf("conflicts: %+v", res.Conflicts)
	}
}

func TestDeletedKeysPropagate(t *testing.T) {
	f := newSyncFixture(t, "")
	b := f.addDevice(t, "desktop")
	if _, err := f.a.Sync(t, settings("a", "1", "b", "2")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Pull(t); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sync(t, settings("a", "1")); err != nil {
		t.Fatal(err)
	}
	got, err := f.a.Pull(t)
	if err != nil || !testkit.Equal(got, settings("a", "1")) {
		t.Fatalf("deletion lost: %v %v", got, err)
	}
}

func TestStaleManifestWriteIsRefusedWithTheCurrentVersion(t *testing.T) {
	f := newSyncFixture(t, "")
	api := f.a.API
	if res := api.Do(t, "PUT", "/v1/sync/manifest", map[string]string{"blob": "AAAA"}); res.Status != http.StatusPreconditionRequired {
		t.Fatalf("a write without If-Match must be refused: %s", res)
	}
	if res := api.Do(t, "PUT", "/v1/sync/manifest", map[string]string{"blob": "AAAA"}, "If-Match", "banana"); res.Status != http.StatusBadRequest {
		t.Fatalf("junk If-Match: %s", res)
	}
	api.Must(t, http.StatusOK, "PUT", "/v1/sync/manifest", map[string]string{"blob": "AAAA"}, "If-Match", "1")
	res := api.Do(t, "PUT", "/v1/sync/manifest", map[string]string{"blob": "BBBB"}, "If-Match", "1")
	if res.Status != http.StatusPreconditionFailed || res.Map(t)["current"].(float64) != 2 {
		t.Fatalf("stale write: %s", res)
	}
	api.Must(t, http.StatusOK, "PUT", "/v1/sync/manifest", map[string]string{"blob": "CCCC"}, "If-Match", "2")
}

func TestAManifestNeedsTheKeySetUpFirst(t *testing.T) {
	e := newEnv(t, "")
	api := e.user(t, "laptop")
	res := api.Do(t, "PUT", "/v1/sync/manifest", map[string]string{"blob": "AAAA"}, "If-Match", "0")
	if res.Status != http.StatusConflict || errorCode(t, res) != "no-key" {
		t.Fatalf("a manifest before the key: %s", res)
	}
	for _, slot := range []string{"passphrase", "recovery"} {
		if res := api.Do(t, "GET", "/v1/sync/wraps/"+slot, nil); res.Status != http.StatusNotFound {
			t.Fatalf("the %s wrap of an account that is not set up: %s", slot, res)
		}
	}
	a := testkit.NewSyncDevice(api)
	a.Create(t, passphrase, recoveryKey)
	if a.KeyVersion != 1 || a.Version != 1 {
		t.Fatalf("set up: key version %d, manifest version %d", a.KeyVersion, a.Version)
	}
	view := api.Must(t, http.StatusOK, "GET", "/v1/sync/manifest", nil).Map(t)
	if view["keyVersion"].(float64) != 1 || view["version"].(float64) != 1 {
		t.Fatalf("manifest after set up: %v", view)
	}
}

func TestServerStoresNoNamesOrValues(t *testing.T) {
	f := newSyncFixture(t, "")
	secret := settings("api-token-name-xyz", "super-secret-value-123")
	secret["notes/private-file.md"] = map[string]string{"line": "private-contents-456"}
	if _, err := f.a.Sync(t, secret); err != nil {
		t.Fatal(err)
	}
	f.env.proc.Stop(t)
	var seen int
	_ = filepath.WalkDir(f.env.proc.DataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		seen++
		raw, _ := os.ReadFile(path)
		for _, needle := range []string{"api-token-name-xyz", "super-secret-value-123", "private-file.md", "private-contents-456", "settings.json"} {
			if bytes.Contains(raw, []byte(needle)) {
				t.Errorf("%s contains plaintext %q", path, needle)
			}
		}
		return nil
	})
	if seen < 3 {
		t.Fatalf("only %d files scanned", seen)
	}
}

func TestDeviceRefusesAManifestOlderThanOneItHasSeen(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "laptop")
	replay := testkit.NewReplayTransport(owner.Client.Transport)
	owner.Client.Transport = replay
	a := testkit.NewSyncDevice(owner)
	a.Create(t, "pw", recoveryKey)

	for _, theme := range []string{"dark", "light", "solarized"} {
		if _, err := a.Sync(t, settings("theme", theme)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Pull(t); err != nil {
		t.Fatal(err)
	}
	if replay.Recorded() < 3 {
		t.Fatalf("recorded %d manifests", replay.Recorded())
	}
	replay.ServeRecorded(0)
	if _, err := a.Pull(t); !errors.Is(err, testkit.ErrStaleManifest) {
		t.Fatalf("a rolled-back manifest was accepted: %v", err)
	}
	if _, err := a.Sync(t, settings("theme", "mine")); !errors.Is(err, testkit.ErrStaleManifest) {
		t.Fatalf("sync against a rolled-back manifest: %v", err)
	}

	fresh := testkit.NewSyncDevice(owner)
	fresh.Key, fresh.KeyVersion = a.Key, a.KeyVersion
	if _, err := fresh.Pull(t); err != nil {
		t.Fatalf("a device that has seen nothing newer cannot tell, and accepts: %v", err)
	}
	replay.ServeRecorded(-1)
	if _, err := a.Pull(t); err != nil {
		t.Fatalf("the honest server must be accepted again: %v", err)
	}
}

func TestNewDeviceCanUnlockWithPassphraseOrRecoveryKey(t *testing.T) {
	f := newSyncFixture(t, "")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	api := f.env.device(t, f.a.API, "second laptop")
	c := testkit.NewSyncDevice(api)
	if err := c.Unlock(t, "passphrase", "wrong"); err == nil {
		t.Fatal("wrong passphrase unlocked the profile key")
	}
	if err := c.Unlock(t, "passphrase", passphrase); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "dark")) {
		t.Fatalf("%v %v", got, err)
	}
	d := testkit.NewSyncDevice(f.env.device(t, f.a.API, "another"))
	if err := d.Unlock(t, "recovery", recoveryKey); err != nil {
		t.Fatalf("recovery key: %v", err)
	}
	if !bytes.Equal(c.Key, d.Key) || !bytes.Equal(c.Key, f.a.Key) {
		t.Fatal("devices ended up with different profile keys")
	}
}

func TestChangingThePassphraseMovesTheKeyVersionAndOtherComputersEnterItOnce(t *testing.T) {
	f := newSyncFixture(t, "")
	b := f.addDevice(t, "desktop")
	if _, err := f.a.Sync(t, settings("theme", "dark", "font", "14")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Pull(t); err != nil {
		t.Fatal(err)
	}
	oldKey := bytes.Clone(f.a.Key)

	if err := f.a.ChangePassphrase(t, "battery staple", "NEWRECOVERYNEWRECOVER"); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldKey, f.a.Key) || f.a.KeyVersion != 2 {
		t.Fatalf("the key was not replaced: key version %d", f.a.KeyVersion)
	}
	if _, err := b.Pull(t); !errors.Is(err, testkit.ErrKeyChanged) {
		t.Fatalf("the other computer must notice the key version moved: %v", err)
	}
	if _, err := b.Sync(t, settings("theme", "light", "font", "14")); !errors.Is(err, testkit.ErrKeyChanged) {
		t.Fatalf("the other computer must not push under the old key: %v", err)
	}
	if err := b.Unlock(t, "passphrase", passphrase); err == nil {
		t.Fatal("the old passphrase still opens the new key")
	}
	if err := b.Unlock(t, "recovery", recoveryKey); err == nil {
		t.Fatal("the old recovery key still opens the new key")
	}
	if err := b.Unlock(t, "passphrase", "battery staple"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Key, f.a.Key) || b.KeyVersion != 2 {
		t.Fatalf("the other computer did not get the new key: key version %d", b.KeyVersion)
	}
	got, err := b.Pull(t)
	if err != nil || !testkit.Equal(got, settings("theme", "dark", "font", "14")) {
		t.Fatalf("the data must survive the key change: %v %v", got, err)
	}
	if _, err := b.Sync(t, settings("theme", "light", "font", "14")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.a.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "light", "font", "14")) {
		t.Fatalf("the first computer after the other's sync: %v %v", got, err)
	}
	for _, slot := range []string{"passphrase", "recovery"} {
		if v := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/wraps/"+slot, nil).Map(t)["keyVersion"]; v != float64(2) {
			t.Fatalf("the %s wrap holds key version %v", slot, v)
		}
	}
}

func TestTheRecoveryKeyUnlocksAndAnyComputerMaySetANewPassphrase(t *testing.T) {
	f := newSyncFixture(t, "")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	c := testkit.NewSyncDevice(f.env.device(t, f.a.API, "new laptop"))
	if err := c.Unlock(t, "recovery", recoveryKey); err != nil {
		t.Fatal(err)
	}
	if err := c.ChangePassphrase(t, "a new passphrase", "NEWRECOVERYNEWRECOVER"); err != nil {
		t.Fatalf("a computer that unlocked with the recovery key replaces the key without approval: %v", err)
	}
	if _, err := f.a.Pull(t); !errors.Is(err, testkit.ErrKeyChanged) {
		t.Fatalf("the first computer must notice: %v", err)
	}
	if err := f.a.Unlock(t, "passphrase", "a new passphrase"); err != nil {
		t.Fatal(err)
	}
	if got, err := f.a.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "dark")) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestKeyReplacementIsAtomicAndChecksTheVersion(t *testing.T) {
	f := newSyncFixture(t, "")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	api := f.a.API
	before := api.Must(t, http.StatusOK, "GET", "/v1/sync/wraps/passphrase", nil).Map(t)
	full := map[string]string{"manifest": "AAAA", "passphrase": "BBBB", "recovery": "CCCC"}
	if res := api.Do(t, "POST", "/v1/sync/rotate", full); res.Status != http.StatusPreconditionRequired {
		t.Fatalf("a replacement without If-Match: %s", res)
	}
	res := api.Do(t, "POST", "/v1/sync/rotate", full, "If-Match", "99")
	if res.Status != http.StatusPreconditionFailed || res.Map(t)["current"].(float64) != 2 {
		t.Fatalf("a stale replacement: %s", res)
	}
	for name, body := range map[string]map[string]string{
		"no recovery wrap":   {"manifest": "AAAA", "passphrase": "BBBB"},
		"no passphrase wrap": {"manifest": "AAAA", "recovery": "CCCC"},
		"no manifest":        {"passphrase": "BBBB", "recovery": "CCCC"},
	} {
		if res := api.Do(t, "POST", "/v1/sync/rotate", body, "If-Match", "2"); res.Status != http.StatusBadRequest {
			t.Errorf("%s: %s", name, res)
		}
	}
	after := api.Must(t, http.StatusOK, "GET", "/v1/sync/wraps/passphrase", nil).Map(t)
	if before["blob"] != after["blob"] || after["keyVersion"] != float64(1) {
		t.Fatalf("a refused replacement changed the key: %v", after)
	}
	if versions := api.Must(t, http.StatusOK, "GET", "/v1/sync/manifest/versions", nil).Map(t)["versions"].([]any); len(versions) != 2 {
		t.Fatalf("a refused replacement wrote a manifest: %v", versions)
	}
	out := api.Must(t, http.StatusOK, "POST", "/v1/sync/rotate", full, "If-Match", "2").Map(t)
	if out["version"] != float64(3) || out["keyVersion"] != float64(2) {
		t.Fatalf("replacement: %v", out)
	}
}

func TestDeviceTrustRoutesAreGone(t *testing.T) {
	f := newSyncFixture(t, "")
	api := f.a.API
	for _, route := range [][2]string{
		{"GET", "/v1/sync/wraps"}, {"PUT", "/v1/sync/wraps/passphrase"}, {"DELETE", "/v1/sync/wraps/recovery"},
		{"GET", "/v1/devices"}, {"POST", "/v1/devices/invite"}, {"DELETE", "/v1/devices/" + api.ID.DeviceID}, {"DELETE", "/v1/account"},
		{"GET", "/v1/auth/elevation"}, {"POST", "/v1/auth/elevation/approval"}, {"POST", "/v1/auth/elevation/github"},
		{"GET", "/v1/auth/approvals"}, {"POST", "/v1/auth/approvals/x/approve"},
	} {
		if res := api.Do(t, route[0], route[1], map[string]string{"blob": "AAAA"}); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %s", route[0], route[1], res)
		}
	}
	if res := api.Do(t, "GET", "/v1/sync/wraps/device:"+api.ID.DeviceID, nil); res.Status != http.StatusBadRequest || errorCode(t, res) != "bad-slot" {
		t.Errorf("a device wrap slot: %s", res)
	}
	info := f.env.anonymous().Must(t, http.StatusOK, "GET", "/v1/info", nil).Map(t)
	for _, gone := range []string{"approverMinAgeSeconds", "syncGCBound", "deviceInactiveAfterSeconds"} {
		if _, ok := info[gone]; ok {
			t.Errorf("/v1/info still has %s", gone)
		}
	}
}

func TestBlobsAreWriteOnceAndQuotaLimited(t *testing.T) {
	f := newSyncFixture(t, "[sync]\nquota_bytes = 300\nmax_blob_bytes = 200\n")
	api := f.a.API
	id := strings.Repeat("A", 43)
	put := func(id string, body []byte) testkit.Response {
		res, err := api.Raw("PUT", "/v1/sync/blobs/"+id, map[string]string{"Content-Type": "application/octet-stream"}, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := put(id, bytes.Repeat([]byte{1}, 100)); res.Status != http.StatusCreated {
		t.Fatalf("first write: %s", res)
	}
	if res := put(id, bytes.Repeat([]byte{1}, 100)); res.Status != http.StatusOK {
		t.Fatalf("identical rewrite must be idempotent: %s", res)
	}
	if res := put(id, bytes.Repeat([]byte{2}, 100)); res.Status != http.StatusConflict {
		t.Fatalf("different content under the same id: %s", res)
	}
	got := api.Must(t, http.StatusOK, "GET", "/v1/sync/blobs/"+id, nil)
	if !bytes.Equal(got.Body, bytes.Repeat([]byte{1}, 100)) {
		t.Fatal("a refused rewrite changed the stored blob")
	}
	if res := put(strings.Repeat("B", 43), bytes.Repeat([]byte{3}, 201)); res.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the blob limit: %s", res)
	}
	if res := put(strings.Repeat("C", 43), bytes.Repeat([]byte{4}, 150)); res.Status != http.StatusCreated {
		t.Fatalf("%s", res)
	}
	if res := put(strings.Repeat("D", 43), bytes.Repeat([]byte{5}, 100)); res.Status != http.StatusInsufficientStorage {
		t.Fatalf("over the quota: %s", res)
	}
	if res := put("short", []byte{1}); res.Status != http.StatusBadRequest {
		t.Fatalf("malformed id: %s", res)
	}
	usage := api.Must(t, http.StatusOK, "GET", "/v1/sync/usage", nil).Map(t)
	if usage["bytes"].(float64) != 250 || usage["blobs"].(float64) != 2 {
		t.Fatalf("usage: %v", usage)
	}
}

func TestGarbageCollectionKeepsOnlyReferencedBlobs(t *testing.T) {
	f := newSyncFixture(t, "[sync]\ngc_grace = \"0s\"\n")
	for _, theme := range []string{"dark", "light", "solarized"} {
		if _, err := f.a.Sync(t, settings("theme", theme)); err != nil {
			t.Fatal(err)
		}
	}
	usage := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/usage", nil).Map(t)
	if usage["blobs"].(float64) != 3 {
		t.Fatalf("usage before gc: %v", usage)
	}
	if deleted := f.a.CollectGarbage(t); deleted != 2 {
		t.Fatalf("deleted %d, want 2", deleted)
	}
	if got, err := f.a.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "solarized")) {
		t.Fatalf("referenced blob lost: %v %v", got, err)
	}
}

func TestManifestHistoryIsKeptForRecovery(t *testing.T) {
	f := newSyncFixture(t, "[sync]\nmanifest_history = 3\n")
	for _, theme := range []string{"a", "b", "c", "d", "e"} {
		if _, err := f.a.Sync(t, settings("theme", theme)); err != nil {
			t.Fatal(err)
		}
	}
	var list struct {
		Versions []struct {
			Version int `json:"version"`
		} `json:"versions"`
	}
	f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/manifest/versions", nil).JSON(t, &list)
	if len(list.Versions) != 3 || list.Versions[0].Version != 6 || list.Versions[2].Version != 4 {
		t.Fatalf("versions: %+v", list.Versions)
	}
	f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/manifest?version=4", nil)
	if res := f.a.API.Do(t, "GET", "/v1/sync/manifest?version=2", nil); res.Status != http.StatusNotFound {
		t.Fatalf("pruned version: %s", res)
	}
}

func TestSyncDataIsIsolatedBetweenAccounts(t *testing.T) {
	f := newSyncFixture(t, "")
	content := []byte(`{"theme":"dark"}`)
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	stranger := f.env.user(t, "stranger")
	if res := stranger.Do(t, "GET", "/v1/sync/manifest", nil); res.Status != http.StatusNotFound {
		t.Fatalf("another account's manifest: %s", res)
	}
	if res := stranger.Do(t, "GET", "/v1/sync/wraps/passphrase", nil); res.Status != http.StatusNotFound {
		t.Fatalf("another account's wrap: %s", res)
	}
	blobID := testkit.BlobID(f.a.Key, "settings.json", content)
	f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/blobs/"+blobID, nil)
	if res := stranger.Do(t, "GET", "/v1/sync/blobs/"+blobID, nil); res.Status != http.StatusNotFound {
		t.Fatalf("another account's blob: %s", res)
	}
	testkit.NewSyncDevice(stranger).Create(t, "stranger", "STRANGERSTRANGERSTRAN")
	if err := f.a.Unlock(t, "passphrase", passphrase); err != nil || f.a.KeyVersion != 1 {
		t.Fatalf("another account's key replacement touched this account: %v %d", err, f.a.KeyVersion)
	}
}

func TestSyncRoutesRequireASession(t *testing.T) {
	e := newEnv(t, "")
	anon := e.anonymous()
	for _, route := range [][2]string{
		{"GET", "/v1/sync/manifest"}, {"PUT", "/v1/sync/manifest"}, {"GET", "/v1/sync/manifest/versions"},
		{"GET", "/v1/sync/blobs/" + strings.Repeat("A", 43)}, {"PUT", "/v1/sync/blobs/" + strings.Repeat("A", 43)},
		{"GET", "/v1/sync/wraps/passphrase"}, {"GET", "/v1/sync/wraps/recovery"},
		{"POST", "/v1/sync/rotate"}, {"POST", "/v1/sync/gc"}, {"GET", "/v1/sync/usage"},
	} {
		if res := anon.Do(t, route[0], route[1], nil); res.Status != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: %s", route[0], route[1], res)
		}
	}
}

func TestSyncModuleCanBeSwitchedOff(t *testing.T) {
	e := newEnvModules(t, "relay = true\npublish = true\nsync = false\npush = false\n", "")
	owner := e.user(t, "laptop")
	if res := owner.Do(t, "GET", "/v1/sync/manifest", nil); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("sync route exists with the module off: %s", res)
	}
}

func TestFloodingManifestsCannotEraseEarlierHistory(t *testing.T) {
	f := newSyncFixture(t, "[sync]\nmanifest_history = 3\n")
	api := f.a.API
	version := int(f.a.Version)
	put := func(blob string) {
		t.Helper()
		res := api.Must(t, http.StatusOK, "PUT", "/v1/sync/manifest", map[string]string{"blob": blob}, "If-Match", fmt.Sprint(version))
		version = int(res.Map(t)["version"].(float64))
	}
	put("QUFB")
	for range 30 {
		put("Rkxv")
	}
	var list struct {
		Versions []struct {
			Version int `json:"version"`
		} `json:"versions"`
	}
	api.Must(t, http.StatusOK, "GET", "/v1/sync/manifest/versions", nil).JSON(t, &list)
	if len(list.Versions) != 3 {
		t.Fatalf("a flood within one day keeps only the newest versions: %d", len(list.Versions))
	}
}

func errorCode(t *testing.T, res testkit.Response) any {
	t.Helper()
	return res.Map(t)["error"]
}

func TestGarbageCollectionNeedsNoApproval(t *testing.T) {
	f := newSyncFixture(t, "[sync]\ngc_grace = \"0s\"\n")
	for _, theme := range []string{"dark", "light"} {
		if _, err := f.a.Sync(t, settings("theme", theme)); err != nil {
			t.Fatal(err)
		}
	}
	if res := f.env.anonymous().Do(t, "POST", "/v1/sync/gc", map[string]any{"keep": []string{}}); res.Status != http.StatusUnauthorized {
		t.Fatalf("garbage collection without a session: %s", res)
	}
	if deleted := f.a.CollectGarbage(t); deleted != 1 {
		t.Fatalf("a signed-in device must be able to collect garbage: deleted %d", deleted)
	}
	if got, err := f.a.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "light")) {
		t.Fatalf("referenced blob lost: %v %v", got, err)
	}
}

func TestGarbageCollectionIsBoundToTheManifestVersion(t *testing.T) {
	f := newSyncFixture(t, "[sync]\ngc_grace = \"0s\"\n")
	for _, theme := range []string{"dark", "light"} {
		if _, err := f.a.Sync(t, settings("theme", theme)); err != nil {
			t.Fatal(err)
		}
	}
	empty := map[string]any{"keep": []string{}}
	if res := f.a.API.Do(t, "POST", "/v1/sync/gc", empty); res.Status != http.StatusPreconditionRequired {
		t.Fatalf("gc without If-Match: %s", res)
	}
	stale := f.a.API.Do(t, "POST", "/v1/sync/gc", empty, "If-Match", "2")
	if stale.Status != http.StatusPreconditionFailed || stale.Map(t)["error"] != "version-mismatch" || stale.Map(t)["current"].(float64) != 3 {
		t.Fatalf("gc against a manifest that moved: %s", stale)
	}
	usage := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/usage", nil).Map(t)
	if usage["blobs"].(float64) != 2 {
		t.Fatalf("a refused gc deleted blobs: %v", usage)
	}
}

func TestGarbageCollectionNeedsTheDevicesSignature(t *testing.T) {
	f := newSyncFixture(t, "[sync]\ngc_grace = \"0s\"\n")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	stolen := stolenCopy(f.env, f.a.API)
	bare := stolen.Do(t, "POST", "/v1/sync/gc", map[string]any{"keep": []string{}}, "If-Match", "2")
	if bare.Status != http.StatusForbidden || bare.Map(t)["error"] != "device-signature-required" {
		t.Fatalf("garbage collection with a bare token: %s", bare)
	}
	if usage := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/usage", nil).Map(t); usage["blobs"].(float64) != 1 {
		t.Fatalf("a bare token deleted blobs: %v", usage)
	}
}

func TestGarbageCollectionAndBlobUploadsNeverLeaveARowWithoutItsFile(t *testing.T) {
	f := newSyncFixture(t, "[sync]\ngc_grace = \"0s\"\n")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	put := func(id string, content []byte) int {
		res, err := f.a.API.Raw("PUT", "/v1/sync/blobs/"+id, map[string]string{"Content-Type": "application/octet-stream"}, bytes.NewReader(content))
		if err != nil {
			t.Error(err)
			return 0
		}
		return res.Status
	}
	for round := range 12 {
		content := []byte(fmt.Sprintf("sealed blob %d", round))
		id := testkit.BlobID(f.a.Key, fmt.Sprintf("race-%d.json", round), content)
		if status := put(id, content); status != http.StatusCreated {
			t.Fatalf("round %d first upload: %d", round, status)
		}
		var wg sync.WaitGroup
		var status int
		wg.Add(2)
		go func() {
			defer wg.Done()
			status = put(id, content)
		}()
		go func() {
			defer wg.Done()
			f.a.API.Do(t, "POST", "/v1/sync/gc", map[string]any{"keep": []string{}}, "If-Match", "2")
		}()
		wg.Wait()
		if status != http.StatusOK && status != http.StatusCreated {
			t.Fatalf("round %d: upload answered %d", round, status)
		}
		res := f.a.API.Do(t, "GET", "/v1/sync/blobs/"+id, nil)
		rows := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/usage", nil).Map(t)["blobs"].(float64)
		switch {
		case res.Status == http.StatusOK && bytes.Equal(res.Body, content) && rows == 1:
		case res.Status == http.StatusNotFound && rows == 0:
		default:
			t.Fatalf("round %d: the row and the file disagree after a concurrent upload and gc: GET %d, %v rows", round, res.Status, rows)
		}
	}
}
