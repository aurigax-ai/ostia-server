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

func TestKeysBeyondTheCapShareOneOverflowBucket(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: time.Hour, Burst: 2, MaxKeys: 3}, clock.now)
	for _, key := range []string{"a", "b", "c"} {
		if !l.Allow(key) {
			t.Fatalf("%s refused", key)
		}
	}
	if !l.Allow("d") || !l.Allow("e") {
		t.Fatal("the overflow bucket refused inside its burst")
	}
	if l.Allow("f") {
		t.Fatal("new keys past the cap do not share one budget")
	}
	if l.Len() != 4 {
		t.Fatalf("the table grew past the cap and its overflow bucket: %d", l.Len())
	}
	if !l.Allow("a") {
		t.Fatal("a key tracked before the cap lost its own bucket")
	}
}

func TestSweepFreesRoomUnderTheCap(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: time.Second, Burst: 1, MaxKeys: 2}, clock.now)
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	clock.t = clock.t.Add(time.Minute)
	l.Sweep()
	if l.Len() != 0 {
		t.Fatalf("refilled buckets were kept: %d", l.Len())
	}
	if !l.Allow("c") || !l.Allow("d") {
		t.Fatal("keys refused after the table was swept")
	}
	if _, ok := l.keys["d"]; !ok {
		t.Fatal("a new key did not get its own bucket once there was room")
	}
}

func TestAllHonoursTheCapToo(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	a := New(Rule{Every: time.Hour, Burst: 1, MaxKeys: 1}, clock.now)
	b := New(Rule{Every: time.Hour, Burst: 5, MaxKeys: 1}, clock.now)
	both := All{a, b}
	both.Allow("x")
	both.Allow("y")
	both.Allow("z")
	if a.Len() > 2 || b.Len() > 2 {
		t.Fatalf("combined limiter grew past its caps: %d %d", a.Len(), b.Len())
	}
}
