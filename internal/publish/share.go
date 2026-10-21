package publish

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/store"
	shareshell "github.com/aurigax-ai/ostia-server/web/share-shell"
)

const (
	shellContentSecurityPolicy  = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src data: blob:; font-src data:; media-src data: blob:; connect-src 'self'; frame-src blob:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
	dataContentSecurityPolicy   = "default-src 'none'; sandbox"
	publicContentSecurityPolicy = "sandbox allow-scripts"
)

var staticAssets = map[string]string{
	"/shell.js":  "text/javascript; charset=utf-8",
	"/crypto.js": "text/javascript; charset=utf-8",
	"/shell.css": "text/css; charset=utf-8",
}

func (s *Service) ShareHandler() http.Handler {
	read := limit.Rule{Every: time.Second, Burst: 120}
	reportRule := limit.Rule{Every: 12 * time.Minute, Burst: 5}
	return s.Guard.PerIP("share.read", read, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := hostLabel(r.Host, s.ShareDomain)
		if !ok {
			http.NotFound(w, r)
			return
		}
		setCommonHeaders(w)
		if r.URL.Path == "/report" && r.Method == http.MethodPost {
			s.Guard.PerIP("share.report", reportRule, httpx.Handle(func(w http.ResponseWriter, r *http.Request) error {
				var in struct {
					Reason string `json:"reason"`
				}
				if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
					return err
				}
				return s.report(w, r, id, in.Reason)
			})).ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if contentType, isAsset := staticAssets[r.URL.Path]; isAsset {
			s.serveAsset(w, r, r.URL.Path[1:], contentType, dataContentSecurityPolicy)
			return
		}
		switch r.URL.Path {
		case "/":
			s.serveRoot(w, r, id)
		case "/meta":
			s.serveMeta(w, r, id)
		case "/blob":
			s.serveBlob(w, r, id)
		default:
			http.NotFound(w, r)
		}
	}))
}

func setCommonHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Cache-Control", "no-store")
}

func (s *Service) serveAsset(w http.ResponseWriter, r *http.Request, name, contentType, policy string) {
	content, err := fs.ReadFile(shareshell.Files, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Security-Policy", policy)
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(content)
	}
}

type availability int

const (
	available availability = iota
	missing
	unavailable
)

func (s *Service) lookup(r *http.Request, id string) (store.Share, availability, error) {
	share, err := s.DB.Share(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return share, missing, nil
	}
	if err != nil {
		return share, missing, err
	}
	switch {
	case share.RemovedAt != 0 || s.expired(share):
		return share, unavailable, nil
	case share.UploadedAt == 0:
		return share, missing, nil
	}
	return share, available, nil
}

func (s *Service) serveRoot(w http.ResponseWriter, r *http.Request, id string) {
	share, state, err := s.lookup(r, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if state == available && share.Mode == ModePublic {
		s.servePublic(w, r, share)
		return
	}
	s.serveAsset(w, r, "index.html", "text/html; charset=utf-8", shellContentSecurityPolicy)
}

func (s *Service) servePublic(w http.ResponseWriter, r *http.Request, share store.Share) {
	f, size, err := s.Blobs.Open(r.Context(), store.ShareBlobKey(share.ID))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", publicContentSecurityPolicy)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if r.Method == http.MethodHead {
		return
	}
	_ = s.DB.CountView(r.Context(), share.ID)
	_, _ = io.Copy(w, f)
}

func (s *Service) serveMeta(w http.ResponseWriter, r *http.Request, id string) {
	share, state, err := s.lookup(r, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Security-Policy", dataContentSecurityPolicy)
	switch state {
	case missing:
		httpx.WriteError(w, r, httpx.ErrNotFound)
	case unavailable:
		httpx.WriteError(w, r, httpx.ErrGone)
	default:
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"v": 1, "mode": share.Mode, "size": share.Size, "salt": httpx.B64(share.Salt), "expiresAt": share.ExpiresAt})
	}
}

func (s *Service) serveBlob(w http.ResponseWriter, r *http.Request, id string) {
	share, state, err := s.lookup(r, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Security-Policy", dataContentSecurityPolicy)
	switch {
	case state == missing || (state == available && share.Mode == ModePublic):
		httpx.WriteError(w, r, httpx.ErrNotFound)
		return
	case state == unavailable:
		httpx.WriteError(w, r, httpx.ErrGone)
		return
	}
	f, size, err := s.Blobs.Open(r.Context(), store.ShareBlobKey(share.ID))
	if err != nil {
		httpx.WriteError(w, r, httpx.ErrNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if r.Method == http.MethodHead {
		return
	}
	_ = s.DB.CountView(r.Context(), share.ID)
	_, _ = io.Copy(w, f)
}
