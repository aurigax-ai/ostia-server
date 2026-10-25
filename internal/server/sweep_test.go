package server

import (
	"errors"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func TestSweepsRunWithPublishSwitchedOff(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules = config.Modules{Relay: false, Publish: false, Sync: true}
	srv, err := New(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	if srv.Publish != nil {
		t.Fatal("publish must be off for this test")
	}

	_, dev, err := srv.DB.RegisterProvider(t.Context(), "github", "h", store.NewDevice{Name: "laptop", SignPub: make([]byte, 32), BoxPub: make([]byte, 32)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	token := ids.Hash("token")
	if _, err := srv.DB.CreateSession(t.Context(), token, dev.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	invite := ids.Hash("code")
	if _, err := srv.DB.CreateInvite(t.Context(), invite, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.DB.CreatePushTicket(t.Context(), ids.Hash("ticket"), dev.AccountID, time.Minute); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Hour)
	srv.sweep(t.Context())

	var sessions, invites int
	if err := srv.DB.CountRows(t.Context(), &sessions, &invites); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || invites != 0 {
		t.Fatalf("expired rows survived the sweep: %d sessions, %d invites", sessions, invites)
	}
	if _, err := srv.DB.SessionDevice(t.Context(), token); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestHTTPServersBoundSlowRequests(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API = "api.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	srv, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	h := srv.newHTTPServer(nil)
	if h.ReadHeaderTimeout <= 0 || h.ReadTimeout <= 0 || h.WriteTimeout <= 0 || h.IdleTimeout <= 0 {
		t.Fatalf("an unbounded phase of a request: %+v", h)
	}
}
