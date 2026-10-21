package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func TestLastSeenMovesOncePerDayAndHasNoTimeOfDay(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.SessionTTL = config.Duration(72 * time.Hour)
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t, ""))
	token := e.session(t, d)
	first := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC).UnixMilli()

	lastSeen := func() int64 {
		t.Helper()
		dev, err := e.svc.DB.Device(t.Context(), d.id)
		if err != nil {
			t.Fatal(err)
		}
		return dev.LastSeen
	}
	if got := lastSeen(); got != first {
		t.Fatalf("after signing in: %d, want the start of the day %d", got, first)
	}

	*e.clock = e.clock.Add(11 * time.Hour)
	if status, _ := e.call(t, "GET", "/v1/devices", token, nil); status != 200 {
		t.Fatalf("%d", status)
	}
	if got := lastSeen(); got != first {
		t.Fatalf("activity later the same day moved last seen to %d", got)
	}

	*e.clock = e.clock.Add(2 * time.Hour)
	next := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC).UnixMilli()
	status, out := e.call(t, "GET", "/v1/devices", token, nil)
	if status != 200 {
		t.Fatalf("%d %v", status, out)
	}
	if listed := int64(out["devices"].([]any)[0].(map[string]any)["lastSeen"].(float64)); listed != next {
		t.Fatalf("the listing shows %d, want the start of the new day %d", listed, next)
	}
	if got := lastSeen(); got != next {
		t.Fatalf("activity on the next day left last seen at %d, want %d", got, next)
	}
}

func TestInvitesCannotBeMintedWithoutAnExpiry(t *testing.T) {
	e := newEnv(t)
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, _, err := e.svc.CreateInvite(t.Context(), "", ttl, false); !errors.Is(err, store.ErrInvalidTTL) {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
}
