package testkit

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"
)

var (
	ErrStaleManifest  = errors.New("stale-manifest")
	ErrKeyUnknown     = errors.New("key-unknown")
	ErrBadWrapCounter = errors.New("bad-wrap-counter")
	ErrSignerTooYoung = errors.New("signer-too-young")
	ErrTooManyRaces   = errors.New("sync lost the race too many times")
)

const maxSyncAttempts = 3

type SyncDevice struct {
	API     *API
	Key     []byte
	Argon   ArgonParams
	Base    Files
	Highest int64
	Version int64

	Approved     []ManifestDevice
	FirstSeen    map[string]int64
	MinSignerAge time.Duration
	Now          func() time.Time
}

func (d *SyncDevice) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func firstSeenKey(dev ManifestDevice) string {
	return fmt.Sprintf("%s|%s|%s|%d", dev.ID, dev.SignPub, dev.BoxPub, dev.CreatedAt)
}

func (d *SyncDevice) trackApproved(devices []ManifestDevice) {
	if d.FirstSeen == nil {
		d.FirstSeen = map[string]int64{}
	}
	for _, dev := range devices {
		if _, ok := d.FirstSeen[firstSeenKey(dev)]; !ok {
			d.FirstSeen[firstSeenKey(dev)] = d.now().UnixMilli()
		}
	}
}

func (d *SyncDevice) signerAge(t testing.TB, dev ManifestDevice) time.Duration {
	t.Helper()
	since := max(dev.CreatedAt, d.FirstSeen[firstSeenKey(dev)])
	for _, listed := range d.Devices(t) {
		if listed.ID == dev.ID {
			since = max(since, listed.CreatedAt)
		}
	}
	return d.now().Sub(time.UnixMilli(since))
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
	d.putWrap(t, "device:"+d.API.ID.DeviceID, d.deviceWrap(t, d.Key, 1, d.API.ID.DeviceID, d.API.ID.BoxPub()))
	d.Approved = []ManifestDevice{manifestDeviceOf(d.API, d.now())}
}

func manifestDeviceOf(api *API, now time.Time) ManifestDevice {
	return ManifestDevice{
		ID:        api.ID.DeviceID,
		Name:      api.ID.Name,
		SignPub:   b64.EncodeToString(api.ID.SignPub()),
		BoxPub:    b64.EncodeToString(api.ID.BoxPub()),
		CreatedAt: now.UnixMilli(),
	}
}

func (d *SyncDevice) approvedWithSelf() []ManifestDevice {
	if !slices.ContainsFunc(d.Approved, func(dev ManifestDevice) bool { return dev.ID == d.API.ID.DeviceID }) {
		d.Approved = append(d.Approved, manifestDeviceOf(d.API, d.now()))
	}
	return d.Approved
}

func (d *SyncDevice) pinned(id string) (ManifestDevice, bool) {
	for _, dev := range d.Approved {
		if dev.ID == id {
			return dev, true
		}
	}
	return ManifestDevice{}, false
}

func (d *SyncDevice) Signer() WrapSigner {
	return WrapSigner{ID: d.API.ID.DeviceID, Sign: d.API.ID.Sign}
}

func (d *SyncDevice) deviceWrap(t testing.TB, key []byte, counter uint64, targetID string, boxPub []byte) []byte {
	t.Helper()
	wrap, err := WrapForDevice(key, d.Signer(), counter, "device:"+targetID, boxPub)
	if err != nil {
		t.Fatal(err)
	}
	return wrap
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

func (d *SyncDevice) openDeviceWrap(t testing.TB, signPub []byte) (DeviceWrap, error) {
	t.Helper()
	slot := "device:" + d.API.ID.DeviceID
	wrap, ok := d.fetchWrap(t, slot)
	if !ok {
		return DeviceWrap{}, ErrKeyUnknown
	}
	return UnwrapForDevice(wrap, slot, d.API.ID.Box, signPub)
}

func (d *SyncDevice) fetchSealedManifest(t testing.TB) (sealed []byte, version int64, ok bool) {
	t.Helper()
	res := d.API.Do(t, "GET", "/v1/sync/manifest", nil)
	if res.Status == http.StatusNotFound {
		return nil, 0, false
	}
	if res.Status != http.StatusOK {
		t.Fatalf("GET manifest: %s", res)
	}
	var view struct {
		Version int64  `json:"version"`
		Blob    string `json:"blob"`
	}
	res.JSON(t, &view)
	sealed, _ = DecodeB64(view.Blob)
	return sealed, view.Version, true
}

func (d *SyncDevice) JoinFromDeviceWrap(t testing.TB, approverSignPub []byte) error {
	t.Helper()
	opened, err := d.openDeviceWrap(t, approverSignPub)
	if err != nil {
		return err
	}
	if opened.Counter < 1 {
		return ErrBadWrapCounter
	}
	if sealed, _, ok := d.fetchSealedManifest(t); ok {
		manifest, err := OpenManifest(opened.Key, sealed)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrKeyUnknown, err)
		}
		if opened.Counter < uint64(manifest.Counter) {
			return ErrBadWrapCounter
		}
	}
	d.Key = opened.Key
	d.Approved = []ManifestDevice{{ID: opened.SignerID, SignPub: b64.EncodeToString(approverSignPub)}}
	d.trackApproved(d.Approved)
	return nil
}

func (d *SyncDevice) rekeyFromPinnedWrap(t testing.TB, sealed []byte) error {
	t.Helper()
	wrap, ok := d.fetchWrap(t, "device:"+d.API.ID.DeviceID)
	if !ok {
		return ErrKeyUnknown
	}
	signerID, ok := ParseWrapSigner(wrap)
	if !ok {
		return ErrWrongKey
	}
	signer, _ := d.pinned(signerID)
	signPub, _ := b64.DecodeString(signer.SignPub)
	opened, err := d.openDeviceWrap(t, signPub)
	if err != nil {
		return err
	}
	if age := d.signerAge(t, signer); age < d.MinSignerAge {
		return fmt.Errorf("%w: %s", ErrSignerTooYoung, age)
	}
	if opened.Counter <= uint64(max(d.Highest, 0)) {
		return ErrBadWrapCounter
	}
	if _, err := OpenManifest(opened.Key, sealed); err != nil {
		return fmt.Errorf("%w: %v", ErrKeyUnknown, err)
	}
	d.Key = opened.Key
	return nil
}

func (d *SyncDevice) GrantDevice(t testing.TB, joiner *API) {
	t.Helper()
	d.putWrap(t, "device:"+joiner.ID.DeviceID, d.deviceWrap(t, d.Key, uint64(max(d.Highest, 1)), joiner.ID.DeviceID, joiner.ID.BoxPub()))
	d.approvedWithSelf()
	if !slices.ContainsFunc(d.Approved, func(dev ManifestDevice) bool { return dev.ID == joiner.ID.DeviceID }) {
		d.Approved = append(d.Approved, manifestDeviceOf(joiner, d.now()))
	}
}

type remoteState struct {
	manifest Manifest
	files    Files
	version  int64
}

func (d *SyncDevice) pull(t testing.TB) (remoteState, error) {
	t.Helper()
	sealed, version, ok := d.fetchSealedManifest(t)
	if !ok {
		return remoteState{files: Files{}}, nil
	}
	manifest, err := OpenManifest(d.Key, sealed)
	if err != nil {
		if rekeyErr := d.rekeyFromPinnedWrap(t, sealed); rekeyErr != nil {
			return remoteState{}, fmt.Errorf("%w: %w", ErrKeyUnknown, rekeyErr)
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
	d.Approved = slices.Clone(manifest.Devices)
	d.trackApproved(d.Approved)
	return remoteState{manifest: manifest, files: files, version: version}, nil
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
			Devices: slices.Clone(d.approvedWithSelf()),
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
	ID      string
	Name    string
	SignPub []byte
	BoxPub  []byte

	CreatedAt int64
}

func (d *SyncDevice) Devices(t testing.TB) []RemoteDevice {
	t.Helper()
	var list struct {
		Devices []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			SignPub string `json:"signPub"`
			BoxPub  string `json:"boxPub"`

			CreatedAt int64 `json:"createdAt"`
		} `json:"devices"`
	}
	d.API.Must(t, http.StatusOK, "GET", "/v1/devices", nil).JSON(t, &list)
	out := make([]RemoteDevice, 0, len(list.Devices))
	for _, dev := range list.Devices {
		sign, _ := DecodeB64(dev.SignPub)
		box, _ := DecodeB64(dev.BoxPub)
		out = append(out, RemoteDevice{ID: dev.ID, Name: dev.Name, SignPub: sign, BoxPub: box, CreatedAt: dev.CreatedAt})
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
	listed := d.Devices(t)
	for _, dev := range d.approvedWithSelf() {
		if dev.ID == removeID || !slices.ContainsFunc(listed, func(l RemoteDevice) bool { return listedMatches(l, dev) }) {
			continue
		}
		boxPub, _ := b64.DecodeString(dev.BoxPub)
		next.Devices = append(next.Devices, dev)
		wraps["device:"+dev.ID] = EncodeB64(d.deviceWrap(t, newKey, uint64(next.Counter), dev.ID, boxPub))
	}
	d.API.Must(t, http.StatusOK, "POST", "/v1/sync/rotate", map[string]any{
		"ifMatch":     remote.version,
		"manifest":    EncodeB64(SealManifest(newKey, next)),
		"wraps":       wraps,
		"deleteSlots": deleteSlots,
	})
	d.Key, d.Highest, d.Approved = newKey, next.Counter, slices.Clone(next.Devices)
}

func listedMatches(listed RemoteDevice, pinned ManifestDevice) bool {
	return listed.ID == pinned.ID && b64.EncodeToString(listed.SignPub) == pinned.SignPub && b64.EncodeToString(listed.BoxPub) == pinned.BoxPub
}

func (d *SyncDevice) CollectGarbage(t testing.TB) int {
	t.Helper()
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
