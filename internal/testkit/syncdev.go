package testkit

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
)

var (
	ErrStaleManifest = errors.New("stale-manifest")
	ErrKeyUnknown    = errors.New("key-unknown")
	ErrTooManyRaces  = errors.New("sync lost the race too many times")
)

const maxSyncAttempts = 3

type SyncDevice struct {
	API     *API
	Key     []byte
	Argon   ArgonParams
	Base    Files
	Highest int64
	Version int64
}

type SyncResult struct {
	Merged    Files
	Conflicts []Conflict
	Version   int64
	Counter   int64
	Attempts  int
	Pushed    int
}

func NewSyncDevice(api *API) *SyncDevice {
	return &SyncDevice{API: api, Argon: FastArgon, Base: Files{}}
}

func (d *SyncDevice) InitAccount(t testing.TB, passphrase, recoveryKey string) {
	t.Helper()
	d.Key = NewProfileKey()
	d.putWrap(t, "passphrase", WrapWithSecret(d.Key, passphrase, d.Argon))
	if recoveryKey != "" {
		d.putWrap(t, "recovery", WrapWithSecret(d.Key, recoveryKey, d.Argon))
	}
	own, err := WrapForDevice(d.Key, d.API.ID.BoxPub())
	if err != nil {
		t.Fatal(err)
	}
	d.putWrap(t, "device:"+d.API.ID.DeviceID, own)
}

func (d *SyncDevice) putWrap(t testing.TB, slot string, wrap []byte) {
	t.Helper()
	d.API.Must(t, http.StatusNoContent, "PUT", "/v1/sync/wraps/"+slot, map[string]string{"blob": EncodeB64(wrap)})
}

func (d *SyncDevice) fetchWrap(t testing.TB, slot string) ([]byte, bool) {
	t.Helper()
	res := d.API.Do(t, "GET", "/v1/sync/wraps/"+slot, nil)
	if res.Status == http.StatusNotFound {
		return nil, false
	}
	if res.Status != http.StatusOK {
		t.Fatalf("GET wrap %s: %s", slot, res)
	}
	blob, err := DecodeB64(res.Map(t)["blob"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return blob, true
}

func (d *SyncDevice) UnlockWithSecret(t testing.TB, slot, secret string) error {
	t.Helper()
	wrap, ok := d.fetchWrap(t, slot)
	if !ok {
		return fmt.Errorf("no %s wrap", slot)
	}
	key, err := UnwrapWithSecret(wrap, secret)
	if err != nil {
		return err
	}
	d.Key = key
	return nil
}

func (d *SyncDevice) UnlockFromDeviceWrap(t testing.TB) error {
	t.Helper()
	wrap, ok := d.fetchWrap(t, "device:"+d.API.ID.DeviceID)
	if !ok {
		return ErrKeyUnknown
	}
	key, err := UnwrapForDevice(wrap, d.API.ID.Box)
	if err != nil {
		return err
	}
	d.Key = key
	return nil
}

func (d *SyncDevice) GrantDevice(t testing.TB, deviceID string, boxPub []byte) {
	t.Helper()
	wrap, err := WrapForDevice(d.Key, boxPub)
	if err != nil {
		t.Fatal(err)
	}
	d.putWrap(t, "device:"+deviceID, wrap)
}

type remoteState struct {
	manifest Manifest
	files    Files
	version  int64
}

func (d *SyncDevice) pull(t testing.TB) (remoteState, error) {
	t.Helper()
	res := d.API.Do(t, "GET", "/v1/sync/manifest", nil)
	if res.Status == http.StatusNotFound {
		return remoteState{files: Files{}}, nil
	}
	if res.Status != http.StatusOK {
		t.Fatalf("GET manifest: %s", res)
	}
	var view struct {
		Version int64  `json:"version"`
		Blob    string `json:"blob"`
	}
	res.JSON(t, &view)
	sealed, _ := DecodeB64(view.Blob)
	manifest, err := OpenManifest(d.Key, sealed)
	if err != nil {
		if rekeyErr := d.UnlockFromDeviceWrap(t); rekeyErr != nil {
			return remoteState{}, fmt.Errorf("%w: %v", ErrKeyUnknown, rekeyErr)
		}
		if manifest, err = OpenManifest(d.Key, sealed); err != nil {
			return remoteState{}, fmt.Errorf("%w: %v", ErrKeyUnknown, err)
		}
	}
	if manifest.Counter < d.Highest {
		return remoteState{}, fmt.Errorf("%w: server offered counter %d, this device has seen %d", ErrStaleManifest, manifest.Counter, d.Highest)
	}
	files := Files{}
	for path, entry := range manifest.Files {
		blob := d.API.Must(t, http.StatusOK, "GET", "/v1/sync/blobs/"+entry.BlobID, nil)
		plain, err := OpenBlob(d.Key, path, blob.Body)
		if err != nil {
			return remoteState{}, fmt.Errorf("blob for %s: %w", path, err)
		}
		if ContentHash(plain) != entry.Hash {
			return remoteState{}, fmt.Errorf("blob for %s does not match the manifest hash", path)
		}
		var keys map[string]string
		if err := json.Unmarshal(plain, &keys); err != nil {
			return remoteState{}, err
		}
		files[path] = keys
	}
	d.Highest = max(d.Highest, manifest.Counter)
	return remoteState{manifest: manifest, files: files, version: view.Version}, nil
}

func encodeFile(keys map[string]string) []byte {
	raw, _ := json.Marshal(keys, json.Deterministic(true))
	return raw
}

func (d *SyncDevice) Pull(t testing.TB) (Files, error) {
	t.Helper()
	state, err := d.pull(t)
	if err != nil {
		return nil, err
	}
	d.Base = state.files.Clone()
	d.Version = state.version
	return state.files, nil
}

func (d *SyncDevice) Sync(t testing.TB, local Files) (SyncResult, error) {
	t.Helper()
	var result SyncResult
	for attempt := 1; attempt <= maxSyncAttempts; attempt++ {
		result.Attempts = attempt
		remote, err := d.pull(t)
		if err != nil {
			return result, err
		}
		merged, conflicts := Merge(d.Base, local, remote.files)
		result.Merged, result.Conflicts = merged, conflicts
		if Equal(merged, remote.files) {
			d.Base, d.Version = merged.Clone(), remote.version
			result.Version, result.Counter = remote.version, remote.manifest.Counter
			return result, nil
		}
		next := Manifest{
			Counter: max(remote.manifest.Counter, d.Highest) + 1,
			Files:   map[string]ManifestFile{},
			Devices: []ManifestDevice{{ID: d.API.ID.DeviceID, Name: d.API.ID.Name}},
		}
		result.Pushed = 0
		for path, keys := range merged {
			content := encodeFile(keys)
			entry := ManifestFile{BlobID: BlobID(d.Key, path, content), Hash: ContentHash(content)}
			next.Files[path] = entry
			if remote.manifest.Files[path] == entry {
				continue
			}
			d.uploadBlob(t, entry.BlobID, SealBlob(d.Key, path, content))
			result.Pushed++
		}
		res := d.API.Do(t, "PUT", "/v1/sync/manifest", map[string]string{"blob": EncodeB64(SealManifest(d.Key, next))},
			"If-Match", fmt.Sprint(remote.version))
		switch res.Status {
		case http.StatusOK:
			d.Highest, d.Base = next.Counter, merged.Clone()
			d.Version = int64(res.Map(t)["version"].(float64))
			result.Version, result.Counter = d.Version, next.Counter
			return result, nil
		case http.StatusPreconditionFailed:
			continue
		default:
			t.Fatalf("PUT manifest: %s", res)
		}
	}
	return result, ErrTooManyRaces
}

func (d *SyncDevice) uploadBlob(t testing.TB, id string, sealed []byte) {
	t.Helper()
	res, err := d.API.Raw("PUT", "/v1/sync/blobs/"+id, map[string]string{"Content-Type": "application/octet-stream"}, bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusCreated && res.Status != http.StatusOK {
		t.Fatalf("PUT blob: %s", res)
	}
}

type RemoteDevice struct {
	ID     string
	Name   string
	BoxPub []byte
}

func (d *SyncDevice) Devices(t testing.TB) []RemoteDevice {
	t.Helper()
	var list struct {
		Devices []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			BoxPub string `json:"boxPub"`
		} `json:"devices"`
	}
	d.API.Must(t, http.StatusOK, "GET", "/v1/devices", nil).JSON(t, &list)
	out := make([]RemoteDevice, 0, len(list.Devices))
	for _, dev := range list.Devices {
		box, _ := DecodeB64(dev.BoxPub)
		out = append(out, RemoteDevice{ID: dev.ID, Name: dev.Name, BoxPub: box})
	}
	return out
}

func (d *SyncDevice) RemoveDeviceAndRotate(t testing.TB, approver *API, removeID, passphrase, recoveryKey string) {
	t.Helper()
	d.API.ElevateByApproval(t, approver)
	d.API.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+removeID, nil)
	remote, err := d.pull(t)
	if err != nil {
		t.Fatal(err)
	}
	newKey := NewProfileKey()
	next := Manifest{Counter: max(remote.manifest.Counter, d.Highest) + 1, Files: map[string]ManifestFile{}}
	for path, keys := range remote.files {
		content := encodeFile(keys)
		entry := ManifestFile{BlobID: BlobID(newKey, path, content), Hash: ContentHash(content)}
		next.Files[path] = entry
		d.uploadBlob(t, entry.BlobID, SealBlob(newKey, path, content))
	}
	wraps := map[string]string{"passphrase": EncodeB64(WrapWithSecret(newKey, passphrase, d.Argon))}
	var deleteSlots []string
	if recoveryKey != "" {
		wraps["recovery"] = EncodeB64(WrapWithSecret(newKey, recoveryKey, d.Argon))
	} else {
		deleteSlots = append(deleteSlots, "recovery")
	}
	for _, dev := range d.Devices(t) {
		next.Devices = append(next.Devices, ManifestDevice{ID: dev.ID, Name: dev.Name})
		wrap, err := WrapForDevice(newKey, dev.BoxPub)
		if err != nil {
			t.Fatal(err)
		}
		wraps["device:"+dev.ID] = EncodeB64(wrap)
	}
	d.API.Must(t, http.StatusOK, "POST", "/v1/sync/rotate", map[string]any{
		"ifMatch":     remote.version,
		"manifest":    EncodeB64(SealManifest(newKey, next)),
		"wraps":       wraps,
		"deleteSlots": deleteSlots,
	})
	d.Key, d.Highest = newKey, next.Counter
}

func (d *SyncDevice) CollectGarbage(t testing.TB, approver *API) int {
	t.Helper()
	d.API.ElevateByApproval(t, approver)
	remote, err := d.pull(t)
	if err != nil {
		t.Fatal(err)
	}
	keep := []string{}
	for _, entry := range remote.manifest.Files {
		keep = append(keep, entry.BlobID)
	}
	slices.Sort(keep)
	m := d.API.Must(t, http.StatusOK, "POST", "/v1/sync/gc", map[string]any{"keep": keep}).Map(t)
	return int(m["deleted"].(float64))
}
