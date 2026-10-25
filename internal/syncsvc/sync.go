package syncsvc

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/blob"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	maxWrapBytes   = 64 << 10
	jsonOverhead   = 4 << 10
	slotPassphrase = "passphrase"
	slotRecovery   = "recovery"
	maxKeepIDs     = 100000
)

type Service struct {
	DB    *store.DB
	Blobs blob.Store
	Auth  *auth.Service
	Cfg   config.Sync

	locks [64]sync.Mutex
}

func (s *Service) lockAccount(accountID string) func() {
	sum := sha256.Sum256([]byte(accountID))
	m := &s.locks[int(sum[0])%len(s.locks)]
	m.Lock()
	return m.Unlock
}

func (s *Service) Mount(mux *httpx.Mux) {
	mux.HandleBulk("GET /v1/sync/manifest", s.Auth.Authed(s.getManifest))
	mux.HandleBulk("PUT /v1/sync/manifest", s.Auth.Authed(s.putManifest))
	mux.Handle("GET /v1/sync/manifest/versions", s.Auth.Authed(s.manifestVersions))
	mux.HandleBulk("GET /v1/sync/blobs/{blobId}", s.Auth.Authed(s.getBlob))
	mux.HandleBulk("PUT /v1/sync/blobs/{blobId}", s.Auth.Authed(s.putBlob))
	mux.Handle("GET /v1/sync/wraps/{slot}", s.Auth.Authed(s.getWrap))
	mux.HandleBulk("POST /v1/sync/rotate", s.Auth.Authed(s.rotate))
	mux.Handle("POST /v1/sync/gc", s.Auth.Authed(s.gc))
	mux.Handle("GET /v1/sync/usage", s.Auth.Authed(s.usage))
}

type manifestView struct {
	Version    int64     `json:"version"`
	KeyVersion int64     `json:"keyVersion"`
	Blob       httpx.B64 `json:"blob"`
	UpdatedAt  int64     `json:"updatedAt"`
}

func (s *Service) getManifest(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	var m store.Manifest
	var err error
	if v := r.URL.Query().Get("version"); v != "" {
		version, parseErr := strconv.ParseInt(v, 10, 64)
		if parseErr != nil {
			return httpx.ErrBadRequest
		}
		m, err = s.DB.ManifestAt(r.Context(), p.AccountID, version)
	} else {
		m, err = s.DB.CurrentManifest(r.Context(), p.AccountID)
	}
	if errors.Is(err, store.ErrNotFound) {
		return httpx.Errf(http.StatusNotFound, "no-manifest", "nothing has been synced yet")
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, manifestView{Version: m.Version, KeyVersion: m.KeyVersion, Blob: m.Blob, UpdatedAt: m.UpdatedAt})
	return nil
}

func (s *Service) manifestVersions(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	versions, err := s.DB.ManifestVersions(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	type entry struct {
		Version    int64 `json:"version"`
		KeyVersion int64 `json:"keyVersion"`
		UpdatedAt  int64 `json:"updatedAt"`
	}
	out := make([]entry, 0, len(versions))
	for _, v := range versions {
		out = append(out, entry{v.Version, v.KeyVersion, v.UpdatedAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"versions": out})
	return nil
}

func ifMatch(r *http.Request) (int64, error) {
	raw := strings.Trim(r.Header.Get("If-Match"), `" `)
	if raw == "" {
		return 0, httpx.Errf(http.StatusPreconditionRequired, "precondition-required", "send If-Match with the manifest version you read (0 for none)")
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version < 0 {
		return 0, httpx.Errf(http.StatusBadRequest, "bad-request", "If-Match must be a manifest version number")
	}
	return version, nil
}

func versionMismatch(w http.ResponseWriter, err error) bool {
	current, ok := store.CurrentOf(err)
	if !ok {
		return false
	}
	httpx.WriteJSON(w, http.StatusPreconditionFailed, map[string]any{"error": "version-mismatch", "current": current})
	return true
}

func (s *Service) manifestLimit() int64 { return s.Cfg.MaxManifestBytes*4/3 + jsonOverhead }

func (s *Service) putManifest(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	expected, err := ifMatch(r)
	if err != nil {
		return err
	}
	stamp, err := s.Auth.SignedTimestamp(r)
	if err != nil {
		return err
	}
	body, err := httpx.ReadBody(w, r, s.manifestLimit())
	if err != nil {
		return err
	}
	if err := s.Auth.RequireSignature(r, p, auth.ManifestPutContext, stamp, auth.ManifestPutFields(expected, body)...); err != nil {
		return err
	}
	var in struct {
		Blob httpx.B64 `json:"blob"`
	}
	if err := httpx.DecodeJSON(body, &in); err != nil {
		return err
	}
	if len(in.Blob) == 0 || int64(len(in.Blob)) > s.Cfg.MaxManifestBytes {
		return httpx.Errf(http.StatusRequestEntityTooLarge, "too-large", "manifest size is outside the allowed range")
	}
	version, err := s.DB.PutManifest(r.Context(), p.AccountID, expected, in.Blob, s.retention())
	if versionMismatch(w, err) {
		return nil
	}
	if errors.Is(err, store.ErrNoKey) {
		return httpx.Errf(http.StatusConflict, "no-key", "set up the sync key with POST /v1/sync/rotate first")
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": version})
	return nil
}

func (s *Service) getBlob(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	id := r.PathValue("blobId")
	if !ids.ValidBlobID(id) {
		return httpx.ErrBadRequest
	}
	if _, err := s.DB.SyncBlob(r.Context(), p.AccountID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	f, size, err := s.Blobs.Open(r.Context(), store.SyncBlobKey(p.AccountID, id))
	if errors.Is(err, blob.ErrNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
	return nil
}

func (s *Service) putBlob(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	id := r.PathValue("blobId")
	if !ids.ValidBlobID(id) {
		return httpx.ErrBadRequest
	}
	if r.ContentLength > s.Cfg.MaxBlobBytes {
		return httpx.ErrTooLarge
	}
	up, err := s.Blobs.Put(r.Context(), store.SyncBlobKey(p.AccountID, id), r.Body, s.Cfg.MaxBlobBytes)
	if errors.Is(err, blob.ErrTooLarge) {
		return httpx.ErrTooLarge
	}
	if err != nil {
		return err
	}
	if up.Size() == 0 {
		up.Abort()
		return httpx.Errf(http.StatusBadRequest, "bad-request", "empty blob")
	}
	sum := up.Sum()
	defer s.lockAccount(p.AccountID)()
	existing, err := s.DB.SyncBlob(r.Context(), p.AccountID, id)
	switch {
	case err == nil:
		if !ids.Equal(existing.Sum, sum[:]) {
			up.Abort()
			return httpx.Errf(http.StatusConflict, "blob-exists", "a blob id is write-once; derive a new id for new content")
		}
		touched, err := s.DB.TouchSyncBlob(r.Context(), p.AccountID, id)
		if err != nil {
			up.Abort()
			return err
		}
		if touched {
			up.Abort()
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "size": existing.Size})
			return nil
		}
	case !errors.Is(err, store.ErrNotFound):
		up.Abort()
		return err
	}
	err = s.DB.AddSyncBlob(r.Context(), p.AccountID, store.SyncBlob{ID: id, Size: up.Size(), Sum: sum[:]}, s.Cfg.QuotaBytes)
	if errors.Is(err, store.ErrQuota) {
		up.Abort()
		return httpx.Errf(http.StatusInsufficientStorage, "quota-exceeded", "the sync storage quota is full")
	}
	if err != nil {
		up.Abort()
		return err
	}
	if err := up.Commit(); err != nil {
		_ = s.DB.DeleteSyncBlob(r.Context(), p.AccountID, id)
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "size": up.Size()})
	return nil
}

type wrapView struct {
	Slot       string    `json:"slot"`
	Blob       httpx.B64 `json:"blob"`
	KeyVersion int64     `json:"keyVersion"`
	UpdatedAt  int64     `json:"updatedAt"`
}

func (s *Service) getWrap(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	slot := r.PathValue("slot")
	if slot != slotPassphrase && slot != slotRecovery {
		return httpx.Errf(http.StatusBadRequest, "bad-slot", "slot must be passphrase or recovery")
	}
	if err := s.Auth.RequireSignedTimestamp(r, p, auth.WrapReadContext, slot); err != nil {
		return err
	}
	key, err := s.DB.SyncKey(r.Context(), p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	blob := key.Passphrase
	if slot == slotRecovery {
		blob = key.Recovery
	}
	httpx.WriteJSON(w, http.StatusOK, wrapView{Slot: slot, Blob: blob, KeyVersion: key.Version, UpdatedAt: key.UpdatedAt})
	return nil
}

func (s *Service) rotateLimit() int64 { return s.manifestLimit() + 2*(maxWrapBytes*4/3) + jsonOverhead }

func (s *Service) rotate(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	expected, err := ifMatch(r)
	if err != nil {
		return err
	}
	stamp, err := s.Auth.SignedTimestamp(r)
	if err != nil {
		return err
	}
	body, err := httpx.ReadBody(w, r, s.rotateLimit())
	if err != nil {
		return err
	}
	if err := s.Auth.RequireSignature(r, p, auth.SyncRotateContext, stamp, auth.ManifestPutFields(expected, body)...); err != nil {
		return err
	}
	var in struct {
		Manifest   httpx.B64 `json:"manifest"`
		Passphrase httpx.B64 `json:"passphrase"`
		Recovery   httpx.B64 `json:"recovery"`
	}
	if err := httpx.DecodeJSON(body, &in); err != nil {
		return err
	}
	if len(in.Manifest) == 0 || int64(len(in.Manifest)) > s.Cfg.MaxManifestBytes {
		return httpx.Errf(http.StatusBadRequest, "bad-request", "manifest size is outside the allowed range")
	}
	for _, wrap := range [][]byte{in.Passphrase, in.Recovery} {
		if len(wrap) == 0 || len(wrap) > maxWrapBytes {
			return httpx.Errf(http.StatusBadRequest, "bad-request", "passphrase and recovery wraps are both required and at most 64 KiB")
		}
	}
	version, keyVersion, err := s.DB.ReplaceKey(r.Context(), p.AccountID, store.KeyReplacement{
		IfMatch: expected, Manifest: in.Manifest, Passphrase: in.Passphrase, Recovery: in.Recovery, Retention: s.retention(),
	})
	if versionMismatch(w, err) {
		return nil
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": version, "keyVersion": keyVersion})
	return nil
}

func (s *Service) gc(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	expected, err := ifMatch(r)
	if err != nil {
		return err
	}
	stamp, err := s.Auth.SignedTimestamp(r)
	if err != nil {
		return err
	}
	body, err := httpx.ReadBody(w, r, int64(maxKeepIDs)*140)
	if err != nil {
		return err
	}
	if err := s.Auth.RequireSignature(r, p, auth.SyncGCContext, stamp, auth.ManifestPutFields(expected, body)...); err != nil {
		return err
	}
	var in struct {
		Keep []string `json:"keep"`
	}
	if err := httpx.DecodeJSON(body, &in); err != nil {
		return err
	}
	if len(in.Keep) > maxKeepIDs {
		return httpx.ErrTooLarge
	}
	keep := make(map[string]bool, len(in.Keep))
	for _, id := range in.Keep {
		keep[id] = true
	}
	defer s.lockAccount(p.AccountID)()
	stale, err := s.DB.CollectSyncBlobs(r.Context(), p.AccountID, expected, keep, s.Cfg.GCGrace.Std())
	if versionMismatch(w, err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, id := range stale {
		if err := s.Blobs.Delete(r.Context(), store.SyncBlobKey(p.AccountID, id)); err != nil {
			return err
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": len(stale)})
	return nil
}

func (s *Service) usage(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	count, bytes, err := s.DB.SyncUsage(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"blobs": count, "bytes": bytes, "quotaBytes": s.Cfg.QuotaBytes})
	return nil
}

func (s *Service) retention() store.Retention {
	return store.Retention{Versions: s.Cfg.ManifestHistory, CheckpointDays: s.Cfg.ManifestCheckpointDays}
}
