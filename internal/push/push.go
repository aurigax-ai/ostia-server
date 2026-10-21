package push

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/serverkey"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	PlatformFCM  = "fcm"
	PlatformAPNs = "apns"

	tokenPurpose  = "push-token"
	maxTokenBytes = 4096
	smallBody     = 8 << 10
	handleExtra   = 6
)

var (
	ErrInvalidToken        = errors.New("push token rejected by the platform")
	ErrPlatformUnavailable = errors.New("push platform not configured")
)

type Sender interface {
	Send(ctx context.Context, platform, token string) error
}

type Service struct {
	DB                   *store.DB
	Key                  *serverkey.Key
	Auth                 *auth.Service
	Guard                *httpx.Guard
	Now                  func() time.Time
	MaxHandles           int
	MaxHandlesPerAccount int
	TicketTTL            time.Duration
	Sender               Sender

	perHandle limit.All
}

func (s *Service) Mount(mux *httpx.Mux) {
	s.perHandle = limit.All{
		limit.New(limit.Rule{Every: 30 * time.Second, Burst: 1}, s.Now),
		limit.New(limit.Rule{Every: time.Minute, Burst: 60}, s.Now),
	}
	mux.Handle("POST /v1/push/tickets", s.Auth.Authed(s.ticket))
	mux.Handle("POST /v1/push/register", s.Guard.PerIP("push.register", limit.Rule{Every: 6 * time.Second, Burst: 10}, httpx.Handle(s.register)))
	mux.Handle("POST /v1/push/{handle}", s.Auth.Authed(s.ping))
	mux.Handle("DELETE /v1/push/{handle}", s.Auth.Authed(s.remove))
}

func (s *Service) Sweep() {
	for _, l := range s.perHandle {
		l.Sweep()
	}
}

func (s *Service) ticket(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	ticket := ids.Token()
	expires, err := s.DB.CreatePushTicket(r.Context(), ids.Hash(ticket), p.AccountID, s.TicketTTL)
	if errors.Is(err, store.ErrLimit) {
		w.Header().Set("Retry-After", "60")
		return httpx.ErrRateLimited
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ticket": ticket, "expiresAt": expires})
	return nil
}

func (s *Service) register(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Platform string `json:"platform"`
		Token    string `json:"token"`
		Ticket   string `json:"ticket"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	if in.Platform != PlatformFCM && in.Platform != PlatformAPNs {
		return httpx.Errf(http.StatusBadRequest, "bad-request", "platform must be fcm or apns")
	}
	if in.Token == "" || len(in.Token) > maxTokenBytes {
		return httpx.Errf(http.StatusBadRequest, "bad-request", "token is empty or too long")
	}
	handle := newHandle()
	_, err := s.DB.RegisterPushHandle(r.Context(), ids.Hash(in.Ticket),
		store.PushHandle{Handle: handle, Platform: in.Platform, TokenSealed: s.Key.Seal(tokenPurpose, []byte(in.Token))},
		s.MaxHandlesPerAccount, s.MaxHandles)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return httpx.Errf(http.StatusForbidden, "invalid-ticket", "ask the desktop for a new registration ticket")
	case errors.Is(err, store.ErrLimit):
		return httpx.Errf(http.StatusServiceUnavailable, "busy", "this account or server cannot take more push registrations")
	default:
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]string{"handle": handle})
	return nil
}

func (s *Service) emptyBody(r *http.Request) error {
	if r.ContentLength > 0 {
		return httpx.Errf(http.StatusBadRequest, "bad-request", "a push ping has no body")
	}
	if r.ContentLength < 0 {
		var one [1]byte
		if n, _ := io.ReadFull(io.LimitReader(r.Body, 1), one[:]); n > 0 {
			return httpx.Errf(http.StatusBadRequest, "bad-request", "a push ping has no body")
		}
	}
	return nil
}

func (s *Service) owned(r *http.Request, p auth.Principal) (store.PushHandle, error) {
	h, err := s.DB.PushHandle(r.Context(), r.PathValue("handle"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && h.AccountID != p.AccountID) {
		return store.PushHandle{}, httpx.ErrGone
	}
	return h, err
}

func (s *Service) ping(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	if err := s.emptyBody(r); err != nil {
		return err
	}
	h, err := s.owned(r, p)
	if err != nil {
		return err
	}
	if !s.perHandle.Allow(h.Handle) {
		w.Header().Set("Retry-After", "30")
		return httpx.ErrRateLimited
	}
	token, err := s.Key.Open(tokenPurpose, h.TokenSealed)
	if err != nil {
		return err
	}
	err = s.Sender.Send(r.Context(), h.Platform, string(token))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
		return nil
	case errors.Is(err, ErrInvalidToken):
		_ = s.DB.DeletePushHandle(r.Context(), h.Handle)
		return httpx.ErrGone
	case errors.Is(err, ErrPlatformUnavailable):
		return httpx.Errf(http.StatusNotImplemented, "platform-unavailable", "this server cannot deliver to that platform")
	}
	slog.Error("push delivery failed", "platform", h.Platform, "err", err)
	return httpx.Errf(http.StatusBadGateway, "delivery-failed", "the push platform did not accept the ping")
}

func (s *Service) remove(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
	h, err := s.owned(r, p)
	if err != nil {
		return httpx.ErrNotFound
	}
	if err := s.DB.DeletePushHandle(r.Context(), h.Handle); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func newHandle() string { return ids.New() + ids.New()[:handleExtra] }
