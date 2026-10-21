package e2e

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

type syncFixture struct {
	env *env
	a   *testkit.SyncDevice
}

func newSyncFixture(t *testing.T, extra string) *syncFixture {
	t.Helper()
	e := newEnv(t, extra)
	owner := e.user(t, "laptop")
	a := testkit.NewSyncDevice(owner)
	a.InitAccount(t, "correct horse", "RECOVERYKEYRECOVERYKE")
	return &syncFixture{env: e, a: a}
}

func (f *syncFixture) addDevice(t *testing.T, name string) *testkit.SyncDevice {
	t.Helper()
	api := f.env.device(t, f.a.API, name)
	d := testkit.NewSyncDevice(api)
	f.a.GrantDevice(t, api.ID.DeviceID, api.ID.BoxPub())
	if err := d.UnlockFromDeviceWrap(t); err != nil {
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
	if err != nil || first.Counter != 1 {
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
	api.Must(t, http.StatusOK, "PUT", "/v1/sync/manifest", map[string]string{"blob": "AAAA"}, "If-Match", "0")
	res := api.Do(t, "PUT", "/v1/sync/manifest", map[string]string{"blob": "BBBB"}, "If-Match", "0")
	if res.Status != http.StatusPreconditionFailed || res.Map(t)["current"].(float64) != 1 {
		t.Fatalf("stale write: %s", res)
	}
	api.Must(t, http.StatusOK, "PUT", "/v1/sync/manifest", map[string]string{"blob": "CCCC"}, "If-Match", "1")
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
	a.InitAccount(t, "pw", "")

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
	fresh.Key = a.Key
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
	if err := c.UnlockWithSecret(t, "passphrase", "wrong"); err == nil {
		t.Fatal("wrong passphrase unlocked the profile key")
	}
	if err := c.UnlockWithSecret(t, "passphrase", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "dark")) {
		t.Fatalf("%v %v", got, err)
	}
	d := testkit.NewSyncDevice(f.env.device(t, f.a.API, "another"))
	if err := d.UnlockWithSecret(t, "recovery", "RECOVERYKEYRECOVERYKE"); err != nil {
		t.Fatalf("recovery key: %v", err)
	}
	if !bytes.Equal(c.Key, d.Key) || !bytes.Equal(c.Key, f.a.Key) {
		t.Fatal("devices ended up with different profile keys")
	}
}

func TestRemovingADeviceRotatesTheKeyForTheRest(t *testing.T) {
	f := newSyncFixture(t, "")
	b := f.addDevice(t, "stolen laptop")
	c := f.addDevice(t, "desktop")
	if _, err := f.a.Sync(t, settings("theme", "dark", "font", "14")); err != nil {
		t.Fatal(err)
	}
	oldKey := bytes.Clone(f.a.Key)

	f.a.RemoveDeviceAndRotate(t, c.API, b.API.ID.DeviceID, "correct horse", "")
	if bytes.Equal(oldKey, f.a.Key) {
		t.Fatal("the profile key was not rotated")
	}
	if res := b.API.Do(t, "GET", "/v1/sync/manifest", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("the removed device still reads the manifest: %s", res)
	}
	if res := b.API.Do(t, "GET", "/v1/sync/wraps/passphrase", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("the removed device still reads wraps: %s", res)
	}
	d := testkit.NewSyncDevice(f.env.device(t, f.a.API, "late joiner"))
	if err := d.UnlockWithSecret(t, "recovery", "RECOVERYKEYRECOVERYKE"); err == nil {
		t.Fatal("the old recovery key must stop working when it is not re-entered")
	}

	got, err := c.Pull(t)
	if err != nil || !testkit.Equal(got, settings("theme", "dark", "font", "14")) {
		t.Fatalf("C must pick up the rotated key from its device wrap: %v %v", got, err)
	}
	if !bytes.Equal(c.Key, f.a.Key) {
		t.Fatal("C did not adopt the new key")
	}
	if _, err := c.Sync(t, settings("theme", "light", "font", "14")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.a.Pull(t); err != nil || !testkit.Equal(got, settings("theme", "light", "font", "14")) {
		t.Fatalf("A after C's sync: %v %v", got, err)
	}
	var wraps struct {
		Wraps []struct {
			Slot string `json:"slot"`
		} `json:"wraps"`
	}
	f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/wraps", nil).JSON(t, &wraps)
	for _, w := range wraps.Wraps {
		if w.Slot == "device:"+b.API.ID.DeviceID || w.Slot == "recovery" {
			t.Errorf("wrap %s survived the rotation", w.Slot)
		}
	}
}

func TestRotationIsAtomicAndChecksTheVersion(t *testing.T) {
	f := newSyncFixture(t, "")
	b := f.addDevice(t, "second laptop")
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	f.a.API.ElevateByApproval(t, b.API)
	before := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/wraps/passphrase", nil).Map(t)["blob"]
	res := f.a.API.Do(t, "POST", "/v1/sync/rotate", map[string]any{
		"ifMatch":  99,
		"manifest": "AAAA",
		"wraps":    map[string]string{"passphrase": "BBBB"},
	})
	if res.Status != http.StatusPreconditionFailed {
		t.Fatalf("stale rotation: %s", res)
	}
	after := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/wraps/passphrase", nil).Map(t)["blob"]
	if before != after {
		t.Fatal("a refused rotation still replaced a wrap")
	}
	if res := f.a.API.Do(t, "POST", "/v1/sync/rotate", map[string]any{"ifMatch": 1, "manifest": "AAAA", "wraps": map[string]string{"device:" + strings.Repeat("a", 26): "BBBB"}}); res.Status != http.StatusNotFound {
		t.Fatalf("wrap for a device outside the account: %s", res)
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
	second := f.addDevice(t, "second laptop")
	for _, theme := range []string{"dark", "light", "solarized"} {
		if _, err := f.a.Sync(t, settings("theme", theme)); err != nil {
			t.Fatal(err)
		}
	}
	usage := f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/usage", nil).Map(t)
	if usage["blobs"].(float64) != 3 {
		t.Fatalf("usage before gc: %v", usage)
	}
	if deleted := f.a.CollectGarbage(t, second.API); deleted != 2 {
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
	if len(list.Versions) != 3 || list.Versions[0].Version != 5 || list.Versions[2].Version != 3 {
		t.Fatalf("versions: %+v", list.Versions)
	}
	f.a.API.Must(t, http.StatusOK, "GET", "/v1/sync/manifest?version=3", nil)
	if res := f.a.API.Do(t, "GET", "/v1/sync/manifest?version=1", nil); res.Status != http.StatusNotFound {
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
	if res := stranger.Do(t, "PUT", "/v1/sync/wraps/device:"+f.a.API.ID.DeviceID, map[string]string{"blob": "AAAA"}); res.Status != http.StatusNotFound {
		t.Fatalf("a wrap for another account's device: %s", res)
	}
}

func TestSyncRoutesRequireASession(t *testing.T) {
	e := newEnv(t, "")
	anon := e.anonymous()
	for _, route := range [][2]string{
		{"GET", "/v1/sync/manifest"}, {"PUT", "/v1/sync/manifest"}, {"GET", "/v1/sync/manifest/versions"},
		{"GET", "/v1/sync/blobs/" + strings.Repeat("A", 43)}, {"PUT", "/v1/sync/blobs/" + strings.Repeat("A", 43)},
		{"GET", "/v1/sync/wraps"}, {"GET", "/v1/sync/wraps/passphrase"}, {"PUT", "/v1/sync/wraps/passphrase"}, {"DELETE", "/v1/sync/wraps/passphrase"},
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

func TestDestructiveSyncActionsNeedAnotherDevicesApproval(t *testing.T) {
	f := newSyncFixture(t, "")
	api := f.a.API
	if _, err := f.a.Sync(t, settings("theme", "dark")); err != nil {
		t.Fatal(err)
	}
	refused := func(what, method, path string, body any) {
		t.Helper()
		res := api.Do(t, method, path, body)
		if res.Status != http.StatusForbidden || res.Map(t)["error"] != "elevation-required" {
			t.Errorf("%s was not refused: %s", what, res)
		}
	}
	wrap := map[string]string{"blob": "AAAA"}
	refused("deleting a wrap", "DELETE", "/v1/sync/wraps/recovery", nil)
	refused("replacing the passphrase wrap", "PUT", "/v1/sync/wraps/passphrase", wrap)
	refused("replacing the recovery wrap", "PUT", "/v1/sync/wraps/recovery", wrap)
	refused("garbage collection", "POST", "/v1/sync/gc", map[string]any{"keep": []string{}})
	refused("rotation", "POST", "/v1/sync/rotate", map[string]any{"ifMatch": 1, "manifest": "AAAA"})
	api.Must(t, http.StatusNoContent, "PUT", "/v1/sync/wraps/device:"+api.ID.DeviceID, wrap)

	other := f.addDevice(t, "second laptop")
	if res := other.API.Do(t, "DELETE", "/v1/sync/wraps/recovery", nil); res.Status != http.StatusForbidden {
		t.Fatalf("the approver is not elevated by approving: %s", res)
	}
	api.ElevateByApproval(t, other.API)
	api.Must(t, http.StatusNoContent, "DELETE", "/v1/sync/wraps/recovery", nil)
	api.Must(t, http.StatusNoContent, "PUT", "/v1/sync/wraps/passphrase", wrap)
}
