package adminui

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func (s *Service) home(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/admin/invites", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", page{Host: s.Host})
}

func (s *Service) refuseLogin(w http.ResponseWriter, status int, message string) {
	s.render(w, status, "login", page{Host: s.Host, Error: message})
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.fail(w, r, err)
		return
	}
	hash := ids.Hash(auth.NormalizeCode(r.PostFormValue("code")))
	hint, err := s.DB.ConsumeAdminCode(r.Context(), hash)
	if err == nil {
		if err := s.startSession(w, r, "code:"+hint); err != nil {
			s.fail(w, r, err)
		}
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	if !s.loginAll.Allow("all") {
		w.Header().Set("Retry-After", retryAfter(loginFailures))
		s.fail(w, r, httpx.ErrRateLimited)
		return
	}
	slog.Warn("admin sign-in refused: unknown, used or expired code")
	s.refuseLogin(w, http.StatusUnauthorized, "That code is unknown, used or expired.")
}

func retryAfter(rule limit.Rule) string { return strconv.Itoa(max(1, int(rule.Every/time.Second))) }
