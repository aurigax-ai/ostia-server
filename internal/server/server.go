package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/blob"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/publish"
	"github.com/aurigax-ai/ostia-server/internal/push"
	"github.com/aurigax-ai/ostia-server/internal/relay"
	"github.com/aurigax-ai/ostia-server/internal/serverkey"
	"github.com/aurigax-ai/ostia-server/internal/sni"
	"github.com/aurigax-ai/ostia-server/internal/store"
	"github.com/aurigax-ai/ostia-server/internal/syncsvc"
)

const (
	apiVersion       = 1
	shutdownGrace    = 5 * time.Second
	readHeaderWait   = 10 * time.Second
	idleConnWait     = 2 * time.Minute
	maintenanceEvery = time.Minute
	httpTimeout      = 10 * time.Second
	tlsHandshakeWait = 10 * time.Second
)

type Options struct {
	Now        func() time.Time
	HTTPClient *http.Client
}

type Server struct {
	Cfg     config.Config
	DB      *store.DB
	Blobs   blob.Store
	Key     *serverkey.Key
	Auth    *auth.Service
	Relay   *relay.Hub
	Publish *publish.Service
	Sync    *syncsvc.Service
	Push    *push.Service
	Guard   *httpx.Guard
	Now     func() time.Time

	api   http.Handler
	mux   *httpx.Mux
	share http.Handler
	certs *certSet
}

func (o Options) now() func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

func (o Options) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{Timeout: httpTimeout}
}

func New(cfg config.Config, opts Options) (*Server, error) {
	now := opts.now()
	if err := mkdirAll(cfg.DataDir); err != nil {
		return nil, err
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "ostia.sqlite"), now)
	if err != nil {
		return nil, err
	}
	blobs, err := blob.NewDisk(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		return nil, err
	}
	key, err := serverkey.Load(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{Cfg: cfg, DB: db, Blobs: blobs, Key: key, Now: now}
	s.Guard = &httpx.Guard{IP: func(r *http.Request) string { return httpx.ClientIP(r, cfg.Listen.ClientIPHeader) }, Now: now}
	s.Auth = &auth.Service{DB: db, Blobs: blobs, Key: key, Cfg: cfg.Auth, Now: now, Guard: s.Guard}
	if cfg.Auth.GitHubClientID != "" {
		s.Auth.GitHub = &auth.GitHub{ClientID: cfg.Auth.GitHubClientID, BaseURL: cfg.Auth.GitHubBaseURL, APIURL: cfg.Auth.GitHubAPIURL, Client: opts.client()}
	}
	mux := httpx.NewMux()
	s.Auth.Mount(mux)
	if cfg.RelayEnabled() {
		s.Relay = relay.New(db, s.Auth, cfg.Relay, cfg.Domains.Relay, now)
		s.Auth.Hooks = auth.Hooks{DeviceRevoked: s.Relay.KickDevice, AccountDeleted: s.Relay.KickDevices}
		s.Relay.Mount(mux)
	}
	if cfg.PublishEnabled() {
		s.Publish = &publish.Service{DB: db, Blobs: blobs, Auth: s.Auth, Cfg: cfg.Publish, APIDomain: cfg.Domains.API, ShareDomain: cfg.Domains.Share, Scheme: cfg.Domains.Scheme, Now: now, Guard: s.Guard}
		s.Publish.MountAPI(mux)
		s.share = s.Publish.ShareHandler()
	}
	if cfg.SyncEnabled() {
		s.Sync = &syncsvc.Service{DB: db, Blobs: blobs, Auth: s.Auth, Cfg: cfg.Sync}
		s.Sync.Mount(mux)
	}
	if cfg.PushEnabled() {
		sender, err := buildSender(cfg.Push, opts.client(), now)
		if err != nil {
			return nil, err
		}
		s.Push = &push.Service{DB: db, Key: key, Guard: s.Guard, Now: now, MaxHandles: cfg.Push.MaxHandles, Sender: sender}
		s.Push.Mount(mux)
	}
	mux.Handle("GET /v1/info", s.Guard.PerIP("info", limit.Rule{Every: time.Second, Burst: 30}, httpx.Handle(s.info)))
	mux.Handle("GET /healthz", s.Guard.PerIP("healthz", limit.Rule{Every: time.Second, Burst: 30}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})))
	s.mux = mux
	s.api = s.apiWrapper(mux)
	if cfg.Listen.HTTPS != "" && cfg.TLS.Mode == config.TLSFiles {
		if s.certs, err = newCertSet(cfg.TLS.Certs); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func buildSender(cfg config.Push, client *http.Client, now func() time.Time) (push.Sender, error) {
	var d push.Dispatcher
	if cfg.FCM.ServiceAccountFile != "" {
		f, err := push.NewFCM(cfg.FCM.ServiceAccountFile, cfg.FCM.Endpoint, client, now)
		if err != nil {
			return nil, err
		}
		d.FCM = f
	}
	if cfg.APNs.KeyFile != "" {
		a, err := push.NewAPNs(cfg.APNs.KeyFile, cfg.APNs.KeyID, cfg.APNs.TeamID, cfg.APNs.Topic, cfg.APNs.Production, cfg.APNs.Endpoint, client, now)
		if err != nil {
			return nil, err
		}
		d.APNs = a
	}
	return d, nil
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) error {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"api": apiVersion,
		"modules": map[string]any{
			"relay":   s.Cfg.RelayEnabled(),
			"publish": s.Cfg.PublishEnabled(),
			"sync":    s.Cfg.SyncEnabled(),
			"push":    s.Cfg.PushEnabled(),
		},
		"auth":        map[string]bool{"invite": true, "github": s.Auth.GitHub != nil},
		"relayDomain": s.Cfg.Domains.Relay,
		"shareDomain": s.Cfg.Domains.Share,
		"limits": map[string]any{
			"shareMaxBytes":  s.Cfg.Publish.MaxFileBytes,
			"allowPublic":    s.Cfg.Publish.AllowPublic,
			"allowNever":     s.Cfg.Publish.AllowNever,
			"syncBlobBytes":  s.Cfg.Sync.MaxBlobBytes,
			"syncQuotaBytes": s.Cfg.Sync.QuotaBytes,
		},
	})
	return nil
}

func (s *Server) apiWrapper(next http.Handler) http.Handler {
	global := s.Guard.PerIP("api.global", limit.Rule{Every: 20 * time.Millisecond, Burst: 200}, next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		global.ServeHTTP(w, r)
	})
}

func hostOnly(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(r.Host)
		switch {
		case host == s.Cfg.Domains.API:
			s.api.ServeHTTP(w, r)
		case s.share != nil && strings.HasSuffix(host, "."+s.Cfg.Domains.Share):
			s.share.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) Routes() []string { return s.mux.Patterns() }

func (s *Server) ReloadCertificates() error {
	if s.certs == nil {
		return nil
	}
	return s.certs.Reload()
}

func (s *Server) Run(ctx context.Context) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	httpServer := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: readHeaderWait, IdleTimeout: idleConnWait, ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)}
	var closers []func()

	if s.Cfg.Listen.HTTP != "" {
		ln, err := net.Listen("tcp", s.Cfg.Listen.HTTP)
		if err != nil {
			return err
		}
		slog.Info("listening", "http", ln.Addr().String())
		wg.Go(func() {
			if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		})
	}
	if s.Cfg.Listen.HTTPS != "" {
		ln, err := net.Listen("tcp", s.Cfg.Listen.HTTPS)
		if err != nil {
			return err
		}
		slog.Info("listening", "https", ln.Addr().String())
		closers = append(closers, func() { _ = ln.Close() })
		terminated := newConnListener(ln.Addr())
		closers = append(closers, func() { _ = terminated.Close() })
		router := s.router(terminated)
		wg.Go(func() {
			if err := router.Serve(ln); err != nil {
				errs <- err
			}
		})
		secured := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: readHeaderWait, IdleTimeout: idleConnWait, ErrorLog: httpServer.ErrorLog}
		if s.Cfg.TLS.Mode == config.TLSFiles {
			wg.Go(func() {
				if err := secured.Serve(terminated); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errs <- err
				}
			})
			closers = append(closers, func() { _ = secured.Close() })
		}
	}
	if s.Relay != nil {
		wg.Go(func() { s.Relay.Run(ctx) })
	}
	if s.Publish != nil {
		wg.Go(func() { s.Publish.Run(ctx) })
	}
	wg.Go(func() { s.maintain(ctx) })

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = httpServer.Shutdown(shutdown)
	for _, c := range closers {
		c()
	}
	if s.Relay != nil {
		s.Relay.Close()
	}
	wg.Wait()
	return errors.Join(runErr, s.DB.Close())
}

func (s *Server) maintain(ctx context.Context) {
	ticker := time.NewTicker(maintenanceEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Guard.Sweep()
			if s.Push != nil {
				s.Push.Sweep()
			}
		}
	}
}

func (s *Server) router(terminated *connListener) *sni.Router {
	r := &sni.Router{
		HelloTimeout: s.Cfg.Relay.HelloTimeout.Std(),
		MaxPending:   s.Cfg.Relay.MaxPendingHellos,
		Classify: func(name string) (sni.Kind, string) {
			if s.Relay != nil {
				if label, ok := s.Relay.Classify(name); ok {
					return sni.Relay, label
				}
			}
			return sni.Other, ""
		},
		OnOther: func(conn net.Conn) {
			if s.Cfg.TLS.Mode == config.TLSForward {
				forwardTo(s.Cfg.TLS.ForwardAddr, conn)
				return
			}
			secured := tls.Server(conn, s.certs.config())
			_ = secured.SetDeadline(time.Now().Add(tlsHandshakeWait))
			if err := secured.Handshake(); err != nil {
				_ = conn.Close()
				return
			}
			_ = secured.SetDeadline(time.Time{})
			terminated.push(secured)
		},
	}
	if s.Relay != nil {
		r.OnRelay = s.Relay.HandlePhone
	} else {
		r.OnRelay = func(conn net.Conn, _ string, _ []byte, _ time.Time) { _ = conn.Close() }
	}
	return r
}

func forwardTo(addr string, conn net.Conn) {
	upstream, err := net.DialTimeout("tcp", addr, httpTimeout)
	if err != nil {
		_ = conn.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	_ = upstream.Close()
}
