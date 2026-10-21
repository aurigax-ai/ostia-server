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

type flowOwner struct {
	accountID string
	tokenHash []byte
}

type flow struct {
	mu         sync.Mutex
	owner      flowOwner
	ip         string
	deviceCode string
	expires    time.Time
	nextPoll   time.Time
	interval   time.Duration
}

func (o flowOwner) is(other flowOwner) bool {
	return o.accountID == other.accountID && ids.Equal(o.tokenHash, other.tokenHash)
}

func (s *Service) startFlow(w http.ResponseWriter, r *http.Request, owner flowOwner) error {
	ip := s.Guard.IP(r)
	s.mu.Lock()
	inFlight := 0
	for id, f := range s.flows {
		if s.Now().After(f.expires) {
			delete(s.flows, id)
		} else if f.ip == ip {
			inFlight++
		}
	}
	total := len(s.flows)
	s.mu.Unlock()
	if inFlight >= maxFlowsPerIP {
		w.Header().Set("Retry-After", "60")
		return httpx.ErrRateLimited
	}
	if total >= maxFlows {
		return httpx.Err(http.StatusServiceUnavailable, "busy")
	}
	code, err := s.GitHub.Start(r.Context())
	if err != nil {
		return httpx.Errf(http.StatusBadGateway, "github-unavailable", "could not start the GitHub device flow")
	}
	interval := pollInterval(code.Interval)
	f := &flow{owner: owner, ip: ip, deviceCode: code.DeviceCode, expires: s.Now().Add(time.Duration(code.ExpiresIn) * time.Second), interval: interval, nextPoll: s.Now().Add(interval)}
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

func (s *Service) githubStart(w http.ResponseWriter, r *http.Request) error {
	return s.startFlow(w, r, flowOwner{})
}

func (s *Service) advanceFlow(w http.ResponseWriter, r *http.Request, flowID string, owner flowOwner) (userID int64, finished bool, err error) {
	s.mu.Lock()
	f := s.flows[flowID]
	s.mu.Unlock()
	if f == nil || !f.owner.is(owner) {
		return 0, false, httpx.Errf(http.StatusNotFound, "unknown-flow", "start the sign-in again")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	if now.After(f.expires) {
		s.dropFlow(flowID)
		return 0, false, httpx.Errf(http.StatusGone, "expired", "the sign-in code expired")
	}
	if now.Before(f.nextPoll) {
		return 0, false, writePending(w, f.interval)
	}
	token, result, err := s.GitHub.Poll(r.Context(), f.deviceCode)
	if err != nil {
		return 0, false, httpx.Errf(http.StatusBadGateway, "github-unavailable", "could not reach GitHub")
	}
	f.nextPoll = now.Add(f.interval)
	switch result {
	case PollPending:
		return 0, false, writePending(w, f.interval)
	case PollSlowDown:
		f.interval += 5 * time.Second
		f.nextPoll = now.Add(f.interval)
		return 0, false, writePending(w, f.interval)
	case PollExpired:
		s.dropFlow(flowID)
		return 0, false, httpx.Errf(http.StatusGone, "expired", "the sign-in code expired")
	case PollDenied:
		s.dropFlow(flowID)
		return 0, false, httpx.Errf(http.StatusForbidden, "denied", "the sign-in was denied")
	}
	userID, err = s.GitHub.UserID(r.Context(), token)
	if err != nil {
		return 0, false, httpx.Errf(http.StatusBadGateway, "github-unavailable", "could not read the GitHub user")
	}
	s.dropFlow(flowID)
	return userID, true, nil
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
	userID, finished, err := s.advanceFlow(w, r, in.FlowID, flowOwner{})
	if err != nil || !finished {
		return err
	}
	acct, dev, err := s.DB.RegisterProvider(r.Context(), providerGitHub, s.providerHashOf(userID), nd, s.Cfg.MaxDevices)
	if errors.Is(err, store.ErrLimit) {
		return httpx.Errf(http.StatusConflict, "device-limit", "the account has reached its device limit")
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, registered{AccountID: acct.ID, DeviceID: dev.ID, Provider: acct.Provider})
	return nil
}

func (s *Service) providerHashOf(userID int64) string {
	return s.providerHash(providerGitHub, strconv.FormatInt(userID, 10))
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
