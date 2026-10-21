package auth

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

type flow struct {
	mu         sync.Mutex
	deviceCode string
	expires    time.Time
	nextPoll   time.Time
	interval   time.Duration
}

func (s *Service) githubStart(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	for id, f := range s.flows {
		if s.Now().After(f.expires) {
			delete(s.flows, id)
		}
	}
	full := len(s.flows) >= maxFlows
	s.mu.Unlock()
	if full {
		return httpx.Err(http.StatusServiceUnavailable, "busy")
	}
	code, err := s.GitHub.Start(r.Context())
	if err != nil {
		return httpx.Errf(http.StatusBadGateway, "github-unavailable", "could not start the GitHub device flow")
	}
	interval := pollInterval(code.Interval)
	f := &flow{deviceCode: code.DeviceCode, expires: s.Now().Add(time.Duration(code.ExpiresIn) * time.Second), interval: interval, nextPoll: s.Now().Add(interval)}
	flowID := ids.Token()
	s.mu.Lock()
	s.flows[flowID] = f
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"flowId":          flowID,
		"userCode":        code.UserCode,
		"verificationUri": code.VerificationURI,
		"interval":        int(interval / time.Second),
		"expiresIn":       code.ExpiresIn,
	})
	return nil
}

func (s *Service) githubPoll(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		registration
		FlowID string `json:"flowId"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	nd, err := in.registration.validate()
	if err != nil {
		return err
	}
	s.mu.Lock()
	f := s.flows[in.FlowID]
	s.mu.Unlock()
	if f == nil {
		return httpx.Errf(http.StatusNotFound, "unknown-flow", "start the sign-in again")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	if now.After(f.expires) {
		s.dropFlow(in.FlowID)
		return httpx.Errf(http.StatusGone, "expired", "the sign-in code expired")
	}
	if now.Before(f.nextPoll) {
		return writePending(w, f.interval)
	}
	token, result, err := s.GitHub.Poll(r.Context(), f.deviceCode)
	if err != nil {
		return httpx.Errf(http.StatusBadGateway, "github-unavailable", "could not reach GitHub")
	}
	f.nextPoll = now.Add(f.interval)
	switch result {
	case PollPending:
		return writePending(w, f.interval)
	case PollSlowDown:
		f.interval += 5 * time.Second
		f.nextPoll = now.Add(f.interval)
		return writePending(w, f.interval)
	case PollExpired:
		s.dropFlow(in.FlowID)
		return httpx.Errf(http.StatusGone, "expired", "the sign-in code expired")
	case PollDenied:
		s.dropFlow(in.FlowID)
		return httpx.Errf(http.StatusForbidden, "denied", "the sign-in was denied")
	}
	userID, err := s.GitHub.UserID(r.Context(), token)
	if err != nil {
		return httpx.Errf(http.StatusBadGateway, "github-unavailable", "could not read the GitHub user")
	}
	s.dropFlow(in.FlowID)
	acct, dev, err := s.DB.RegisterProvider(r.Context(), providerGitHub, s.providerHash(providerGitHub, strconv.FormatInt(userID, 10)), nd, s.Cfg.MaxDevices)
	if errors.Is(err, store.ErrLimit) {
		return httpx.Errf(http.StatusConflict, "device-limit", "the account has reached its device limit")
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, registered{AccountID: acct.ID, DeviceID: dev.ID, Provider: acct.Provider})
	return nil
}

func (s *Service) dropFlow(id string) {
	s.mu.Lock()
	delete(s.flows, id)
	s.mu.Unlock()
}

func writePending(w http.ResponseWriter, interval time.Duration) error {
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "pending", "interval": int(interval / time.Second)})
	return nil
}
