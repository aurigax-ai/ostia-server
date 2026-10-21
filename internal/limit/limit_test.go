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
	if slow.keys["k"].Value.(*bucket).tokens != 4 {
		t.Fatalf("refused request still consumed from the other limiter: %v", slow.keys["k"].Value.(*bucket).tokens)
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

func TestTheOldestKeyIsEvictedWhenTheTableIsFull(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: time.Hour, Burst: 2, MaxKeys: 3}, clock.now)
	for _, key := range []string{"a", "b", "c"} {
		l.Allow(key)
		l.Allow(key)
		if l.Allow(key) {
			t.Fatalf("%s got past its burst", key)
		}
	}
	l.Allow("a")
	if !l.Allow("d") {
		t.Fatal("a new key was refused instead of getting its own bucket")
	}
	if l.Len() != 3 {
		t.Fatalf("the table grew past the cap: %d", l.Len())
	}
	if _, ok := l.keys["b"]; ok {
		t.Fatal("the least recently used key (b) was kept")
	}
	for _, key := range []string{"a", "c", "d"} {
		if _, ok := l.keys[key]; !ok {
			t.Fatalf("%s was evicted", key)
		}
	}
	for range 2 {
		if !l.Allow("b") {
			t.Fatal("an evicted key did not start over with a full burst")
		}
	}
}

func TestAFloodOfNewKeysNeverStarvesALaterNewKey(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: time.Hour, Burst: 1, MaxKeys: 100}, clock.now)
	for i := range 10000 {
		l.Allow(string(rune('a'+i%26)) + string(rune(i)))
	}
	if l.Len() != 100 {
		t.Fatalf("table size %d", l.Len())
	}
	if !l.Allow("a real client") {
		t.Fatal("a new client shared a budget with the flood")
	}
}

func TestSweepFreesRoomUnderTheCap(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := New(Rule{Every: time.Second, Burst: 1, MaxKeys: 2}, clock.now)
	l.Allow("a")
	l.Allow("b")
	clock.t = clock.t.Add(time.Minute)
	l.Sweep()
	if l.Len() != 0 || l.order.Len() != 0 {
		t.Fatalf("refilled buckets were kept: %d %d", l.Len(), l.order.Len())
	}
	l.Allow("c")
	clock.t = clock.t.Add(500 * time.Millisecond)
	l.Allow("d")
	clock.t = clock.t.Add(700 * time.Millisecond)
	l.Sweep()
	if _, ok := l.keys["d"]; !ok || l.Len() != 1 || l.order.Len() != 1 {
		t.Fatalf("sweep kept the wrong buckets: %d %d", l.Len(), l.order.Len())
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
	if a.Len() != 1 || b.Len() != 1 {
		t.Fatalf("combined limiter grew past its caps: %d %d", a.Len(), b.Len())
	}
}
