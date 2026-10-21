package publish

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/blob"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	ModeLink     = "link"
	ModePassword = "password"
	ModePublic   = "public"

	saltBytes         = 16
	smallBody         = 4 << 10
	staleUploadAfter  = time.Hour
	headerDeleteToken = "X-Delete-Token"
)

var reportReasons = map[string]bool{"illegal": true, "malware": true, "abuse": true, "other": true}

type Service struct {
	DB        *store.DB
	Blobs     blob.Store
	Auth      *auth.Service
	Cfg       config.Publish
	APIDomain string
	Scheme    string
	Port      int
	Now       func() time.Time
	Guard     *httpx.Guard
}

func (s *Service) authority(host string) string {
	if (s.Scheme == "https" && s.Port == 443) || (s.Scheme == "http" && s.Port == 80) {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(s.Port))
}

func (s *Service) shareURL(id string) string {
	return s.Scheme + "://" + s.authority(s.APIDomain) + SharePrefix + id
}

func (s *Service) uploadURL(id string) string {
	return s.Scheme + "://" + s.authority(s.APIDomain) + "/v1/shares/" + id + "/blob"
}

func (s *Service) MountAPI(mux *httpx.Mux) {
	mux.Handle("POST /v1/shares", s.Auth.Authed(s.create))
	mux.Handle("GET /v1/shares", s.Auth.Authed(s.list))
	mux.HandleBulk("PUT /v1/shares/{id}/blob", s.Auth.Authed(s.upload))
	mux.Handle("DELETE /v1/shares/{id}", s.Guard.PerIP("shares.delete", limit.Rule{Every: time.Second, Burst: 30}, httpx.Handle(s.delete)))
	mux.Handle("POST /v1/report/{id}", s.Guard.PerIP("report", limit.Rule{Every: 12 * time.Minute, Burst: 5}, httpx.Handle(s.reportByID)))
}

type createRequest struct {
	Mode             string    `json:"mode"`
	Size             int64     `json:"size"`
	ExpiresInSeconds *int64    `json:"expiresInSeconds"`
	Salt             httpx.B64 `json:"salt"`
}

func (s *Service) expiry(requested *int64) (int64, error) {
	if requested == nil {
		return s.Now().Add(s.Cfg.DefaultExpiry.Std()).UnixMilli(), nil
	}
	if *requested == 0 {
		if !s.Cfg.AllowNever {
			return 0, httpx.Errf(http.StatusBadRequest, "bad-request", "this server does not allow shares that never expire")
		}
		return 0, nil
	}
	d := time.Duration(*requested) * time.Second
	if d < s.Cfg.MinExpiry.Std() || d > s.Cfg.MaxExpiry.Std() {
		return 0, httpx.Errf(http.StatusBadRequest, "bad-request", "expiresInSeconds is outside the allowed range")
	}
	return s.Now().Add(d).UnixMilli(), nil
}

func (s *Service) create(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	var in createRequest
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	switch in.Mode {
	case ModeLink:
	case ModePassword:
		if len(in.Salt) != saltBytes {
			return httpx.Errf(http.StatusBadRequest, "bad-request", "password shares need a 16 byte salt")
		}
	case ModePublic:
		if !s.Cfg.AllowPublic {
			return httpx.Errf(http.StatusForbidden, "public-disabled", "this server does not allow public shares")
		}
	default:
		return httpx.Errf(http.StatusBadRequest, "bad-request", "mode must be link, password or public")
	}
	if in.Mode != ModePassword {
		in.Salt = nil
	}
	if in.Size <= 0 || in.Size > s.Cfg.MaxFileBytes {
		return httpx.Errf(http.StatusRequestEntityTooLarge, "too-large", "size must be between 1 byte and the server's file limit")
	}
	expiresAt, err := s.expiry(in.ExpiresInSeconds)
	if err != nil {
		return err
	}
	acct, err := s.DB.Account(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	if acct.PublishDisabled {
		return httpx.Errf(http.StatusForbidden, "publish-disabled", "publishing is disabled for this account")
	}
	deleteToken := ids.Token()
	share := store.Share{
		ID: ids.New(), AccountID: p.AccountID, Mode: in.Mode, Salt: in.Salt, Size: in.Size,
		ExpiresAt: expiresAt, DeleteTokenHash: ids.Hash(deleteToken),
	}
	err = s.DB.CreateShare(r.Context(), share, store.ShareQuota{MaxShares: s.Cfg.MaxSharesPerAccount, MaxBytes: s.Cfg.MaxBytesPerAccount})
	if errors.Is(err, store.ErrQuota) {
		return httpx.Errf(http.StatusInsufficientStorage, "quota-exceeded", "delete a share or wait for one to expire")
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":          share.ID,
		"url":         s.shareURL(share.ID),
		"uploadUrl":   s.uploadURL(share.ID),
		"deleteToken": deleteToken,
		"expiresAt":   expiresAt,
	})
	return nil
}

func (s *Service) owned(r *http.Request, p auth.Principal) (store.Share, error) {
	share, err := s.DB.Share(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && share.AccountID != p.AccountID) {
		return store.Share{}, httpx.ErrNotFound
	}
	return share, err
}

func (s *Service) upload(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	share, err := s.owned(r, p)
	if err != nil {
		return err
	}
	if share.RemovedAt != 0 {
		return httpx.ErrGone
	}
	if share.UploadedAt != 0 {
		return httpx.Errf(http.StatusConflict, "already-uploaded", "a share's content can be uploaded once")
	}
	if r.ContentLength >= 0 && r.ContentLength != share.Size {
		return httpx.Errf(http.StatusBadRequest, "size-mismatch", "the body must be exactly the declared size")
	}
	up, err := s.Blobs.Put(r.Context(), store.ShareBlobKey(share.ID), r.Body, share.Size)
	if errors.Is(err, blob.ErrTooLarge) {
		return httpx.Errf(http.StatusBadRequest, "size-mismatch", "the body is larger than the declared size")
	}
	if err != nil {
		return err
	}
	if up.Size() != share.Size {
		up.Abort()
		return httpx.Errf(http.StatusBadRequest, "size-mismatch", "the body must be exactly the declared size")
	}
	if err := s.DB.MarkUploaded(r.Context(), share.ID); err != nil {
		up.Abort()
		if errors.Is(err, store.ErrConflict) {
			return httpx.Errf(http.StatusConflict, "already-uploaded", "a share's content can be uploaded once")
		}
		return err
	}
	if err := up.Commit(); err != nil {
		_ = s.DB.DeleteShare(r.Context(), share.ID)
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type shareView struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Mode      string `json:"mode"`
	Size      int64  `json:"size"`
	Views     int64  `json:"views"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Uploaded  bool   `json:"uploaded"`
	Expired   bool   `json:"expired,omitzero"`
}

func (s *Service) expired(sh store.Share) bool {
	return sh.ExpiresAt != 0 && sh.ExpiresAt <= s.Now().UnixMilli()
}

func (s *Service) list(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	shares, err := s.DB.SharesOf(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	out := make([]shareView, 0, len(shares))
	for _, sh := range shares {
		out = append(out, shareView{
			ID: sh.ID, URL: s.shareURL(sh.ID), Mode: sh.Mode, Size: sh.Size, Views: sh.Views,
			CreatedAt: sh.CreatedAt, ExpiresAt: sh.ExpiresAt, Uploaded: sh.UploadedAt != 0, Expired: s.expired(sh),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"shares": out})
	return nil
}

func (s *Service) delete(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	share, err := s.DB.Share(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !s.mayDelete(r, share) {
		return httpx.ErrNotFound
	}
	if err := s.Remove(r.Context(), share); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) mayDelete(r *http.Request, share store.Share) bool {
	if token := r.Header.Get(headerDeleteToken); token != "" {
		return ids.Equal(ids.Hash(token), share.DeleteTokenHash)
	}
	if r.Header.Get("Authorization") == "" {
		return false
	}
	p, err := s.Auth.Authenticate(r)
	return err == nil && p.AccountID == share.AccountID
}

func (s *Service) Remove(ctx context.Context, share store.Share) error {
	if err := s.Blobs.Delete(ctx, store.ShareBlobKey(share.ID)); err != nil {
		return err
	}
	return s.DB.DeleteShare(ctx, share.ID)
}

func (s *Service) TakeDown(ctx context.Context, id string) error {
	if err := s.DB.TakeDown(ctx, id); err != nil {
		return err
	}
	return s.Blobs.Delete(ctx, store.ShareBlobKey(id))
}

func (s *Service) reportByID(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	return s.report(w, r, r.PathValue("id"), in.Reason)
}

func (s *Service) report(w http.ResponseWriter, r *http.Request, id, reason string) error {
	if !reportReasons[reason] {
		return httpx.Errf(http.StatusBadRequest, "bad-request", "reason must be illegal, malware, abuse or other")
	}
	share, err := s.DB.Share(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && share.RemovedAt != 0) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := s.DB.AddReport(r.Context(), id, reason); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) Sweep(ctx context.Context) {
	due, err := s.DB.SweepableShares(ctx, staleUploadAfter)
	if err != nil {
		slog.Error("find expired shares", "err", err)
		return
	}
	for _, share := range due {
		if err := s.Remove(ctx, share); err != nil {
			slog.Error("remove expired share", "err", err)
		}
	}
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(s.Cfg.SweepInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sweep(ctx)
		}
	}
}
