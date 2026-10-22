package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

func TestAnyRequestOrAHeartbeatMovesLastSeenOncePerHour(t *testing.T) {
	e := newEnv(t)
	e.svc.Cfg.SessionTTL = config.Duration(72 * time.Hour)
	e.svc.InactiveAfter = 90 * 24 * time.Hour
	d := newDevice("desktop")
	e.signIn(t, d, e.invite(t, ""))
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
	e.call(t, "GET", "/v1/devices", token, nil)
	if got := lastSeen(); got != first {
		t.Fatalf("activity within the hour moved last seen to %d", got)
	}
	*e.clock = e.clock.Add(31 * time.Minute)
	status, out := e.call(t, "GET", "/v1/devices", token, nil)
	if status != 200 {
		t.Fatalf("%d %v", status, out)
	}
	second := lastSeen()
	if second != e.clock.UnixMilli() {
		t.Fatalf("a request after an hour left last seen at %d, want %d", second, e.clock.UnixMilli())
	}
	row := out["devices"].([]any)[0].(map[string]any)
	if int64(row["lastSeenAt"].(float64)) != second || int64(row["removeAt"].(float64)) != second+e.svc.InactiveAfter.Milliseconds() {
		t.Fatalf("the listing shows lastSeenAt/removeAt %v", row)
	}
	if _, old := row["lastSeen"]; old {
		t.Fatalf("lastSeen is replaced by lastSeenAt: %v", row)
	}
	*e.clock = e.clock.Add(2 * time.Hour)
	if status, _ := e.call(t, "POST", "/v1/devices/heartbeat", token, nil); status != 204 {
		t.Fatalf("heartbeat %d", status)
	}
	if got := lastSeen(); got != e.clock.UnixMilli() {
		t.Fatalf("a heartbeat must check the device in: %d", got)
	}
	if status, _ := e.call(t, "POST", "/v1/devices/heartbeat", "", nil); status != 401 {
		t.Fatalf("a heartbeat needs a session: %d", status)
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
