package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func (s *Service) NeedElevation(p Principal) error {
	if p.ElevatedUntil > s.Now().UnixMilli() {
		return nil
	}
	return httpx.Errf(http.StatusForbidden, "elevation-required", "approve this action from another signed-in device or sign in with GitHub again, then repeat it")
}

func (s *Service) mountElevation(mux *httpx.Mux) {
	mux.Handle("GET /v1/auth/elevation", s.Authed(s.elevationStatus))
	mux.Handle("POST /v1/auth/elevation/approval", s.Authed(s.requestApproval))
	mux.Handle("GET /v1/auth/approvals", s.Authed(s.listApprovals))
	mux.Handle("GET /v1/auth/approvals/{id}", s.Authed(s.approvalStatus))
	mux.Handle("POST /v1/auth/approvals/{id}/approve", s.Authed(s.approve))
	mux.Handle("DELETE /v1/auth/approvals/{id}", s.Authed(s.cancelApproval))
	if s.GitHub != nil {
		mux.Handle("POST /v1/auth/elevation/github", s.Authed(s.elevateGitHubStart))
		mux.Handle("POST /v1/auth/elevation/github/poll", s.Authed(s.elevateGitHubPoll))
	}
}

func (s *Service) elevationStatus(w http.ResponseWriter, _ *http.Request, p Principal) error {
	until := p.ElevatedUntil
	if until <= s.Now().UnixMilli() {
		until = 0
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int64{"elevatedUntil": until})
	return nil
}

func (s *Service) requestApproval(w http.ResponseWriter, r *http.Request, p Principal) error {
	count, err := s.DB.ActiveDeviceCount(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	if count < 2 {
		return httpx.Errf(http.StatusConflict, "no-second-device", "another signed-in device must approve; this account has only one")
	}
	a, err := s.DB.CreateApproval(r.Context(), p.AccountID, p.DeviceID, p.TokenHash, s.Cfg.ApprovalTTL.Std())
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"approvalId": a.ID, "expiresAt": a.ExpiresAt})
	return nil
}

func (s *Service) listApprovals(w http.ResponseWriter, r *http.Request, p Principal) error {
	pending, err := s.DB.PendingApprovals(r.Context(), p.AccountID, p.DeviceID)
	if err != nil {
		return err
	}
	type entry struct {
		ID              string `json:"id"`
		DeviceID        string `json:"deviceId"`
		DeviceName      string `json:"deviceName"`
		DeviceCreatedAt int64  `json:"deviceCreatedAt"`
		CreatedAt       int64  `json:"createdAt"`
		ExpiresAt       int64  `json:"expiresAt"`
	}
	out := make([]entry, 0, len(pending))
	for _, a := range pending {
		out = append(out, entry{a.ID, a.RequesterDeviceID, a.RequesterName, a.RequesterCreated, a.CreatedAt, a.ExpiresAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"approvals": out})
	return nil
}

func (s *Service) approvalStatus(w http.ResponseWriter, r *http.Request, p Principal) error {
	a, err := s.DB.ApprovalOf(r.Context(), r.PathValue("id"), p.TokenHash)
	if errors.Is(err, store.ErrNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	if a.ApprovedAt == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "pending", "expiresAt": a.ExpiresAt})
		return nil
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "approved", "elevatedUntil": p.ElevatedUntil})
	return nil
}

func (s *Service) approve(w http.ResponseWriter, r *http.Request, p Principal) error {
	approver, err := s.DB.Device(r.Context(), p.DeviceID)
	if err != nil {
		return err
	}
	if min := s.Cfg.ApproverMinAge.Std(); min > 0 && s.Now().Sub(time.UnixMilli(approver.CreatedAt)) < min {
		return httpx.Errf(http.StatusForbidden, "device-too-new", "this device joined recently; its approvals are accepted once it has been part of the account long enough")
	}
	until := s.Now().Add(s.Cfg.ElevationTTL.Std()).UnixMilli()
	err = s.DB.Approve(r.Context(), r.PathValue("id"), p.AccountID, p.DeviceID, until)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
		return nil
	case errors.Is(err, store.ErrConflict):
		return httpx.Errf(http.StatusForbidden, "forbidden", "a device cannot approve its own request")
	case errors.Is(err, store.ErrNotFound):
		return httpx.ErrNotFound
	}
	return err
}

func (s *Service) cancelApproval(w http.ResponseWriter, r *http.Request, p Principal) error {
	if err := s.DB.DeleteApproval(r.Context(), r.PathValue("id"), p.AccountID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) elevateGitHubStart(w http.ResponseWriter, r *http.Request, p Principal) error {
	provider, _, err := s.DB.ProviderIdentity(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	if provider != providerGitHub {
		return httpx.Errf(http.StatusConflict, "not-a-github-account", "this account did not sign in with GitHub")
	}
	return s.startFlow(w, r, flowOwner{accountID: p.AccountID, tokenHash: p.TokenHash})
}

func (s *Service) elevateGitHubPoll(w http.ResponseWriter, r *http.Request, p Principal) error {
	var in struct {
		FlowID string `json:"flowId"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	userID, finished, err := s.advanceFlow(w, r, in.FlowID, flowOwner{accountID: p.AccountID, tokenHash: p.TokenHash})
	if err != nil || !finished {
		return err
	}
	_, idHash, err := s.DB.ProviderIdentity(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	if s.providerHashOf(userID) != idHash {
		return httpx.Errf(http.StatusForbidden, "wrong-account", "that GitHub user is not the owner of this account")
	}
	until := s.Now().Add(s.Cfg.ElevationTTL.Std()).UnixMilli()
	if err := s.DB.Elevate(r.Context(), p.TokenHash, until); err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int64{"elevatedUntil": until})
	return nil
}
