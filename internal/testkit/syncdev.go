package testkit

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"testing"
)

var (
	ErrStaleManifest = errors.New("stale-manifest")
	ErrKeyUnknown    = errors.New("key-unknown")
	ErrKeyChanged    = errors.New("key-changed")
	ErrTooManyRaces  = errors.New("sync lost the race too many times")
)

const maxSyncAttempts = 3

type SyncDevice struct {
	API        *API
	Key        []byte
	KeyVersion int64
	Argon      ArgonParams
	Base       Files
	Highest    int64
	Version    int64
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

func (d *SyncDevice) Create(t testing.TB, passphrase, recoveryKey string) {
	t.Helper()
	d.replaceKey(t, 0, Files{}, passphrase, recoveryKey)
}

func (d *SyncDevice) ChangePassphrase(t testing.TB, passphrase, recoveryKey string) error {
	t.Helper()
	remote, err := d.pull(t)
	if err != nil {
		return err
	}
	d.replaceKey(t, remote.version, remote.files, passphrase, recoveryKey)
	return nil
}

func (d *SyncDevice) replaceKey(t testing.TB, ifMatch int64, files Files, passphrase, recoveryKey string) {
	t.Helper()
	key := NewProfileKey()
	next := Manifest{Counter: d.Highest + 1, Files: map[string]ManifestFile{}}
	for path, keys := range files {
		content := encodeFile(keys)
		entry := ManifestFile{BlobID: BlobID(key, path, content), Hash: ContentHash(content)}
		next.Files[path] = entry
		d.uploadBlob(t, entry.BlobID, SealBlob(key, path, content))
	}
	res := d.API.Must(t, http.StatusOK, "POST", "/v1/sync/rotate", map[string]string{
		"manifest":   EncodeB64(SealManifest(key, next)),
		"passphrase": EncodeB64(WrapWithSecret(key, passphrase, d.Argon)),
		"recovery":   EncodeB64(WrapWithSecret(key, recoveryKey, d.Argon)),
	}, "If-Match", strconv.FormatInt(ifMatch, 10))
	var out struct {
		Version    int64 `json:"version"`
		KeyVersion int64 `json:"keyVersion"`
	}
	res.JSON(t, &out)
	d.Key, d.KeyVersion, d.Highest, d.Version, d.Base = key, out.KeyVersion, next.Counter, out.Version, files.Clone()
}

type wrapView struct {
	Blob       string `json:"blob"`
	KeyVersion int64  `json:"keyVersion"`
}

func (d *SyncDevice) Unlock(t testing.TB, slot, secret string) error {
	t.Helper()
	res := d.API.Do(t, "GET", "/v1/sync/wraps/"+slot, nil)
	if res.Status != http.StatusOK {
		return fmt.Errorf("GET wrap %s: %s", slot, res)
	}
	var view wrapView
	res.JSON(t, &view)
	wrap, err := DecodeB64(view.Blob)
	if err != nil {
		return err
	}
	key, err := UnwrapWithSecret(wrap, secret)
	if err != nil {
		return err
	}
	d.Key, d.KeyVersion = key, view.KeyVersion
	return nil
}

type sealedManifest struct {
	sealed     []byte
	version    int64
	keyVersion int64
}

func (d *SyncDevice) fetchSealedManifest(t testing.TB) (sealedManifest, bool) {
	t.Helper()
	res := d.API.Do(t, "GET", "/v1/sync/manifest", nil)
	if res.Status == http.StatusNotFound {
		return sealedManifest{}, false
	}
	if res.Status != http.StatusOK {
		t.Fatalf("GET manifest: %s", res)
	}
	var view struct {
		Version    int64  `json:"version"`
		KeyVersion int64  `json:"keyVersion"`
		Blob       string `json:"blob"`
	}
	res.JSON(t, &view)
	sealed, _ := DecodeB64(view.Blob)
	return sealedManifest{sealed: sealed, version: view.Version, keyVersion: view.KeyVersion}, true
}

type remoteState struct {
	manifest Manifest
	files    Files
	version  int64
}

func (d *SyncDevice) pull(t testing.TB) (remoteState, error) {
	t.Helper()
	fetched, ok := d.fetchSealedManifest(t)
	if !ok {
		return remoteState{files: Files{}}, nil
	}
	if fetched.keyVersion != d.KeyVersion {
		return remoteState{}, fmt.Errorf("%w: the server is at key version %d, this device holds %d", ErrKeyChanged, fetched.keyVersion, d.KeyVersion)
	}
	manifest, err := OpenManifest(d.Key, fetched.sealed)
	if err != nil {
		return remoteState{}, fmt.Errorf("%w: %v", ErrKeyUnknown, err)
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
	return remoteState{manifest: manifest, files: files, version: fetched.version}, nil
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
	m := d.API.Must(t, http.StatusOK, "POST", "/v1/sync/gc", map[string]any{"keep": keep}, "If-Match", strconv.FormatInt(remote.version, 10)).Map(t)
	return int(m["deleted"].(float64))
}
