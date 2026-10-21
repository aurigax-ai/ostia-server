package limit

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestAllowsBurstThenRefills(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: 10 * time.Second, Burst: 3}, clock.now)
	for i := range 3 {
		if !l.Allow("a") {
			t.Fatalf("request %d inside the burst was refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("request beyond the burst was allowed")
	}
	if !l.Allow("b") {
		t.Fatal("another key shares the bucket")
	}
	clock.t = clock.t.Add(10 * time.Second)
	if !l.Allow("a") {
		t.Fatal("a token was not refilled after one interval")
	}
	if l.Allow("a") {
		t.Fatal("more than one token refilled")
	}
}

func TestAllConsumesNothingWhenOneRefuses(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	fast := New(Rule{Every: time.Hour, Burst: 1}, clock.now)
	slow := New(Rule{Every: time.Second, Burst: 5}, clock.now)
	both := All{slow, fast}
	if !both.Allow("k") {
		t.Fatal("first request refused")
	}
	if both.Allow("k") {
		t.Fatal("second request allowed past the one-per-hour rule")
	}
	if slow.keys["k"].tokens != 4 {
		t.Fatalf("refused request still consumed from the other limiter: %v", slow.keys["k"].tokens)
	}
}

func TestSweepDropsIdleKeys(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: time.Second, Burst: 2}, clock.now)
	l.Allow("a")
	if l.Len() != 1 {
		t.Fatal("key missing")
	}
	clock.t = clock.t.Add(5 * time.Second)
	l.Sweep()
	if l.Len() != 0 {
		t.Fatal("idle key kept")
	}
}
