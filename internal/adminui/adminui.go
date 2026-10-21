package adminui

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/serverkey"
	"github.com/aurigax-ai/ostia-server/internal/store"
	adminweb "github.com/aurigax-ai/ostia-server/web/admin"
)

const (
	CodeTTL    = 10 * time.Minute
	SessionTTL = 8 * time.Hour

	cookieName  = "ostia_admin"
	csrfPurpose = "admin-csrf"
	formLimit   = 4 << 10
	csp         = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)

var (
	loginFailures = limit.Rule{Every: 2 * time.Second, Burst: 30}
)

type Service struct {
	DB           *store.DB
	Auth         *auth.Service
	Key          *serverkey.Key
	Guard        *httpx.Guard
	Host         string
	MaxInviteTTL time.Duration
	Now          func() time.Time

	pages    map[string]*template.Template
	loginAll *limit.Limiter
}

type session struct {
	admin string
	token string
	csrf  string
}

type handler func(w http.ResponseWriter, r *http.Request, sess session) error

func IssueCode(ctx context.Context, db *store.DB) (string, error) {
	code := auth.FormatCode(ids.New()[:20])
	hint := strings.ToUpper(auth.NormalizeCode(code)[:4])
	if err := db.CreateAdminCode(ctx, ids.Hash(auth.NormalizeCode(code)), hint, CodeTTL); err != nil {
		return "", err
	}
	return code, db.AddAudit(ctx, "cli", "login-code", hint)
}

func (s *Service) Handler() http.Handler {
	s.pages = parsePages(s.Now)
	s.loginAll = limit.New(loginFailures, s.Now)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusSeeOther) })
	mux.HandleFunc("GET /admin/{$}", s.home)
	mux.HandleFunc("GET /admin/assets/{name}", s.asset)
	slow := limit.Rule{Every: 12 * time.Second, Burst: 5}
	mux.Handle("POST /admin/login", s.Guard.PerIP("admin.login", slow, http.HandlerFunc(s.login)))
	mux.Handle("POST /admin/logout", s.authed(s.logout, true))
	mux.Handle("GET /admin/invites", s.authed(s.invites, false))
	mux.Handle("POST /admin/invites", s.authed(s.createInvite, true))
	mux.Handle("POST /admin/invites/revoke", s.authed(s.revokeInvite, true))
	mux.Handle("GET /admin/accounts", s.authed(s.accounts, false))
	mux.Handle("GET /admin/accounts/{id}", s.authed(s.accounts, false))
	mux.Handle("GET /admin/accounts/{id}/delete", s.authed(s.accounts, false))
	mux.Handle("POST /admin/accounts/{id}/delete", s.authed(s.deleteAccount, true))
	limited := s.Guard.PerIP("admin.global", limit.Rule{Every: 50 * time.Millisecond, Burst: 100}, mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		limited.ServeHTTP(w, r)
	})
}

func (s *Service) authed(fn handler, mutating bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			} else {
				http.Error(w, "sign in required", http.StatusUnauthorized)
			}
			return
		}
		if mutating {
			if err := parseForm(w, r); err != nil {
				s.fail(w, r, err)
				return
			}
			if !ids.Equal([]byte(r.PostFormValue("csrf")), []byte(sess.csrf)) {
				slog.Warn("admin request refused: bad csrf token", "pattern", r.Pattern)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		if err := fn(w, r, sess); err != nil {
			s.fail(w, r, err)
		}
	})
}

func (s *Service) session(r *http.Request) (session, bool) {
	for _, cookie := range r.CookiesNamed(cookieName) {
		if cookie.Value == "" {
			continue
		}
		if admin, err := s.DB.AdminSession(r.Context(), ids.Hash(cookie.Value)); err == nil {
			return session{admin: admin, token: cookie.Value, csrf: csrfToken(s.Key, cookie.Value)}, true
		}
	}
	return session{}, false
}

func (s *Service) startSession(w http.ResponseWriter, r *http.Request, admin string) error {
	token := ids.Token()
	if err := s.DB.CreateAdminSession(r.Context(), ids.Hash(token), admin, SessionTTL); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/admin", MaxAge: int(SessionTTL / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	s.audit(r.Context(), admin, "login", "")
	http.Redirect(w, r, "/admin/invites", http.StatusSeeOther)
	return nil
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request, sess session) error {
	if err := s.DB.DeleteAdminSession(r.Context(), ids.Hash(sess.token)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	s.audit(r.Context(), sess.admin, "logout", "")
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	return nil
}

func csrfToken(key *serverkey.Key, sessionToken string) string {
	return hex.EncodeToString(key.MAC(csrfPurpose, []byte(sessionToken)))
}

func (s *Service) audit(ctx context.Context, admin, action, target string) {
	slog.Info("admin action", "admin", admin, "action", action, "target", target)
	if err := s.DB.AddAudit(ctx, admin, action, target); err != nil {
		slog.Error("write admin audit", "action", action, "err", err)
	}
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	if err := r.ParseForm(); err != nil {
		return httpx.ErrBadRequest
	}
	return nil
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	apiErr, ok := errors.AsType[*httpx.Error](err)
	if !ok {
		slog.Error("admin request failed", "method", r.Method, "pattern", r.Pattern, "err", err)
		apiErr = httpx.Err(http.StatusInternalServerError, "internal")
	}
	for k, v := range apiErr.Header {
		w.Header()[k] = v
	}
	http.Error(w, http.StatusText(apiErr.Status), apiErr.Status)
}

func (s *Service) render(w http.ResponseWriter, status int, name string, data page) {
	var out bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&out, "doc", data); err != nil {
		slog.Error("render admin page", "page", name, "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(out.Bytes())
}

func (s *Service) base(sess session, nav string) page {
	return page{Host: s.Host, Admin: sess.admin, CSRF: sess.csrf, Nav: nav}
}

var assets = map[string]string{"admin.css": "text/css; charset=utf-8", "admin.js": "text/javascript; charset=utf-8"}

func (s *Service) asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	contentType, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(adminweb.Files, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(body)
}
