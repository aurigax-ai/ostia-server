package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func TestRequestsMoveLastSeenOncePerHour(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.SessionTTL = config.Duration(72 * time.Hour)
	e.svc.InactiveAfter = 90 * 24 * time.Hour
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t))
	token := e.session(t, d)
	lastSeen := func() int64 {
		t.Helper()
		dev, err := e.svc.DB.Device(t.Context(), d.id)
		if err != nil {
			t.Fatal(err)
		}
		return dev.LastSeenAt
	}
	first := lastSeen()
	if first != e.clock.UnixMilli() {
		t.Fatalf("after signing in: %d, want %d", first, e.clock.UnixMilli())
	}
	*e.clock = e.clock.Add(30 * time.Minute)
	if status := e.alive(t, token); status != 204 {
		t.Fatalf("heartbeat %d", status)
	}
	if got := lastSeen(); got != first {
		t.Fatalf("activity within the hour moved last seen to %d", got)
	}
	*e.clock = e.clock.Add(31 * time.Minute)
	if status := e.alive(t, token); status != 204 {
		t.Fatalf("heartbeat %d", status)
	}
	if got := lastSeen(); got != e.clock.UnixMilli() {
		t.Fatalf("a request after an hour left last seen at %d, want %d", got, e.clock.UnixMilli())
	}
	if status, _ := e.call(t, "POST", "/v1/devices/heartbeat", "", nil); status != 401 {
		t.Fatalf("a heartbeat needs a session: %d", status)
	}
}

func TestInvitesCannotBeMintedWithoutAnExpiry(t *testing.T) {
	e := newEnv(t)
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, _, err := e.svc.CreateInvite(t.Context(), ttl); !errors.Is(err, store.ErrInvalidTTL) {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
}
