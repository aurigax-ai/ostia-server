package adminui

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	CallbackPath = "/admin/github/callback"
	finishPath   = "/admin/github/finish"
	oauthCookie  = "ostia_admin_oauth"
	oauthTTL     = 10 * time.Minute

	maxCodeLen  = 512
	maxStateLen = 128
	maxErrorLen = 64
)

var (
	startRule  = limit.Rule{Every: 12 * time.Second, Burst: 5}
	returnRule = limit.Rule{Every: 6 * time.Second, Burst: 10}
)

func (s *Service) home(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/admin/invites", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, "")
}

func (s *Service) renderLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	exists, err := s.DB.HasAdmin(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, status, "login", page{Host: s.Host, Setup: !exists, Error: message})
}

func (s *Service) refuse(w http.ResponseWriter, r *http.Request, status int, reason, who, message string) {
	slog.Warn("admin sign-in refused", "reason", reason)
	s.audit(r.Context(), "anonymous", "refused", strings.TrimSpace(reason+" "+who))
	s.renderLogin(w, r, status, message)
}

func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.fail(w, r, err)
		return
	}
	exists, err := s.DB.HasAdmin(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	var codeHash []byte
	switch {
	case exists && code != "":
		s.refuse(w, r, http.StatusConflict, "admin-exists", "", "An admin is already set up on this server.")
		return
	case !exists:
		codeHash = ids.Hash(auth.NormalizeCode(code))
		if err := s.DB.SetupCodeValid(r.Context(), codeHash); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.fail(w, r, err)
				return
			}
			if !s.loginAll.Allow("all") {
				w.Header().Set("Retry-After", retryAfter(loginFailures))
				s.fail(w, r, httpx.ErrRateLimited)
				return
			}
			s.refuse(w, r, http.StatusUnauthorized, "setup-code", "", "That setup code is unknown, used or expired.")
			return
		}
	}
	state, verifier := ids.Token(), ids.Token()
	if err := s.DB.CreateAdminOAuth(r.Context(), ids.Hash(state), verifier, codeHash, oauthTTL); err != nil {
		s.fail(w, r, err)
		return
	}
	challenge := sha256.Sum256([]byte(verifier))
	setOAuthCookie(w, state, int(oauthTTL/time.Second))
	s.render(w, http.StatusOK, "hop", page{Host: s.Host, Next: s.GitHub.AuthorizeURL(s.RedirectURI, state, base64.RawURLEncoding.EncodeToString(challenge[:]))})
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q.Get("code")) > maxCodeLen || len(q.Get("state")) > maxStateLen || len(q.Get("error")) > maxErrorLen {
		s.fail(w, r, httpx.ErrBadRequest)
		return
	}
	next := url.Values{}
	for _, key := range []string{"code", "state", "error"} {
		if v := q.Get(key); v != "" {
			next.Set(key, v)
		}
	}
	s.render(w, http.StatusOK, "hop", page{Host: s.Host, Next: finishPath + "?" + next.Encode()})
}

func (s *Service) finish(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	bound := false
	for _, c := range r.CookiesNamed(oauthCookie) {
		if state != "" && ids.Equal([]byte(c.Value), []byte(state)) {
			bound = true
		}
	}
	setOAuthCookie(w, "", -1)
	if !bound {
		s.refuse(w, r, http.StatusBadRequest, "state-mismatch", "", "This sign-in did not start in this browser. Start again.")
		return
	}
	verifier, codeHash, err := s.DB.TakeAdminOAuth(r.Context(), ids.Hash(state))
	if errors.Is(err, store.ErrNotFound) {
		s.refuse(w, r, http.StatusBadRequest, "state-unknown", "", "This sign-in was already used or has expired. Start again.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		s.refuse(w, r, http.StatusForbidden, "github-denied", "", "GitHub did not authorise the sign-in.")
		return
	}
	user, err := s.githubUser(r, q.Get("code"), verifier)
	if err != nil {
		slog.Error("admin sign-in: github request failed", "err", err)
		s.refuse(w, r, http.StatusBadGateway, "github-unavailable", "", "GitHub could not be reached or refused the code. Try again.")
		return
	}
	id := strconv.FormatInt(user.ID, 10)
	name := "github:" + user.Login
	if len(codeHash) > 0 {
		s.claim(w, r, codeHash, user, name, id)
		return
	}
	if err := s.DB.SignInAdmin(r.Context(), user.ID, user.Login); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.refuse(w, r, http.StatusForbidden, "not-admin", id, "That GitHub account is not an admin of this server.")
			return
		}
		s.fail(w, r, err)
		return
	}
	if err := s.startSession(w, r, name, "login", id); err != nil {
		s.fail(w, r, err)
	}
}

func (s *Service) claim(w http.ResponseWriter, r *http.Request, codeHash []byte, user auth.GitHubUser, name, id string) {
	_, err := s.DB.ClaimFirstAdmin(r.Context(), codeHash, user.ID, user.Login)
	switch {
	case errors.Is(err, store.ErrAdminExists):
		s.refuse(w, r, http.StatusConflict, "admin-exists", id, "An admin is already set up on this server.")
	case errors.Is(err, store.ErrNotFound):
		s.refuse(w, r, http.StatusUnauthorized, "setup-code", id, "That setup code is unknown, used or expired.")
	case err != nil:
		s.fail(w, r, err)
	default:
		if err := s.startSession(w, r, name, "setup", id); err != nil {
			s.fail(w, r, err)
		}
	}
}

func (s *Service) githubUser(r *http.Request, code, verifier string) (auth.GitHubUser, error) {
	token, err := s.GitHub.Exchange(r.Context(), s.ClientSecret, code, s.RedirectURI, verifier)
	if err != nil {
		return auth.GitHubUser{}, err
	}
	return s.GitHub.User(r.Context(), token)
}

func setOAuthCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: value, Path: "/admin/github", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func retryAfter(rule limit.Rule) string { return strconv.Itoa(max(1, int(rule.Every/time.Second))) }
