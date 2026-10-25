package adminui

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/store"
	adminweb "github.com/aurigax-ai/ostia-server/web/admin"
)

type page struct {
	Host  string
	Admin string
	CSRF  string
	Nav   string
	Error string
	Setup bool
	Next  string

	TTLs       []ttlChoice
	NewCode    string
	NewExpires int64
	Open       []store.AdminInvite
	Used       []store.AdminInvite

	Accounts   []store.AccountSummary
	TotalBytes int64
	Selected   *store.AccountSummary
	DeviceList []store.Device
	Confirm    bool
}

type ttlChoice struct {
	Value string
	Label string
	TTL   time.Duration
}

var inviteTTLs = []ttlChoice{{"7d", "7 days", 7 * 24 * time.Hour}, {"1d", "1 day", 24 * time.Hour}, {"1h", "1 hour", time.Hour}}

func (s *Service) ttlChoices() []ttlChoice {
	var out []ttlChoice
	for _, c := range inviteTTLs {
		if c.TTL <= s.MaxInviteTTL {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		out = []ttlChoice{{"max", s.MaxInviteTTL.String(), s.MaxInviteTTL}}
	}
	return out
}

var inviteID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func parsePages(now func() time.Time) map[string]*template.Template {
	funcs := template.FuncMap{
		"ago":   func(ms int64) string { return ago(now(), ms) },
		"until": func(ms int64) string { return until(now(), ms) },
		"day":   func(ms int64) string { return time.UnixMilli(ms).UTC().Format("2 Jan") },
		"stamp": func(ms int64) string { return time.UnixMilli(ms).UTC().Format("2 Jan 15:04") },
		"size":  size,
		"upper": strings.ToUpper,
		"short": short,
		"hint": func(h string) string {
			if h == "" {
				return "older code"
			}
			return h
		},
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"login", "hop", "invites", "accounts"} {
		pages[name] = template.Must(template.New(name).Funcs(funcs).ParseFS(adminweb.Files, "base.html", name+".html"))
	}
	return pages
}

func ago(now time.Time, ms int64) string {
	d := max(now.Sub(time.UnixMilli(ms)), 0)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d/time.Hour))
	}
	return fmt.Sprintf("%d days ago", int((d+12*time.Hour)/(24*time.Hour)))
}

func until(now time.Time, ms int64) string {
	d := time.UnixMilli(ms).Sub(now)
	switch {
	case d < time.Minute:
		return "in under a minute"
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %d h", int((d+30*time.Minute)/time.Hour))
	}
	return fmt.Sprintf("in %d days", int((d+12*time.Hour)/(24*time.Hour)))
}

func size(n int64) string {
	const unit = 1000
	switch {
	case n < unit:
		return fmt.Sprintf("%d B", n)
	case n < unit*unit:
		return fmt.Sprintf("%d KB", n/unit)
	case n < unit*unit*unit:
		return mega(float64(n) / (unit * unit))
	}
	return fmt.Sprintf("%.1f GB", float64(n)/(unit*unit*unit))
}

func mega(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1f MB", v)
	}
	return fmt.Sprintf("%.0f MB", v)
}

func short(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:4] + "…" + id[len(id)-4:]
}

func (s *Service) invites(w http.ResponseWriter, r *http.Request, sess session) error {
	return s.renderInvites(w, r, sess, "", 0)
}

func (s *Service) renderInvites(w http.ResponseWriter, r *http.Request, sess session, newCode string, expires int64) error {
	open, used, err := s.DB.AdminInvites(r.Context())
	if err != nil {
		return err
	}
	data := s.base(sess, "invites")
	data.Open, data.Used, data.NewCode, data.NewExpires, data.TTLs = open, used, newCode, expires, s.ttlChoices()
	s.render(w, http.StatusOK, "invites", data)
	return nil
}

func (s *Service) createInvite(w http.ResponseWriter, r *http.Request, sess session) error {
	var ttl time.Duration
	for _, c := range s.ttlChoices() {
		if c.Value == r.PostFormValue("ttl") {
			ttl = c.TTL
		}
	}
	if ttl == 0 {
		return httpx.ErrBadRequest
	}
	code, expires, err := s.Auth.CreateInvite(r.Context(), "", ttl)
	if err != nil {
		return err
	}
	s.audit(r.Context(), sess.admin, "invite.create", auth.CodeHint(code))
	return s.renderInvites(w, r, sess, code, expires)
}

func (s *Service) revokeInvite(w http.ResponseWriter, r *http.Request, sess session) error {
	id := r.PostFormValue("id")
	if !inviteID.MatchString(id) {
		return httpx.ErrBadRequest
	}
	hint, err := s.DB.RevokeInvite(r.Context(), id)
	if err != nil {
		return notFound(err)
	}
	s.audit(r.Context(), sess.admin, "invite.revoke", hint)
	http.Redirect(w, r, "/admin/invites", http.StatusSeeOther)
	return nil
}

func (s *Service) accounts(w http.ResponseWriter, r *http.Request, sess session) error {
	id := r.PathValue("id")
	if id != "" && !ids.ValidID(id) {
		return httpx.ErrNotFound
	}
	list, err := s.DB.AccountSummaries(r.Context())
	if err != nil {
		return err
	}
	data := s.base(sess, "accounts")
	data.Accounts = list
	for i, a := range list {
		data.TotalBytes += a.Bytes
		if a.ID == id {
			data.Selected = &list[i]
		}
	}
	if id != "" {
		if data.Selected == nil {
			return httpx.ErrNotFound
		}
		if data.DeviceList, err = s.DB.DevicesOf(r.Context(), id); err != nil {
			return err
		}
		data.Confirm = r.URL.Path == "/admin/accounts/"+id+"/delete"
	}
	s.render(w, http.StatusOK, "accounts", data)
	return nil
}

func (s *Service) deleteAccount(w http.ResponseWriter, r *http.Request, sess session) error {
	id := r.PathValue("id")
	if !ids.ValidID(id) {
		return httpx.ErrNotFound
	}
	if err := s.Auth.DeleteAccount(r.Context(), id); err != nil {
		return err
	}
	s.audit(r.Context(), sess.admin, "account.delete", id)
	http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
	return nil
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return httpx.ErrNotFound
	}
	return err
}
