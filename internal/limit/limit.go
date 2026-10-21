package limit

import (
	"sync"
	"time"
)

const (
	DefaultMaxKeys = 50000
	overflowKey    = "\x00overflow"
)

type Rule struct {
	Every   time.Duration
	Burst   int
	MaxKeys int
}

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	rule Rule
	now  func() time.Time
	mu   sync.Mutex
	keys map[string]*bucket
}

func New(rule Rule, now func() time.Time) *Limiter {
	if rule.MaxKeys <= 0 {
		rule.MaxKeys = DefaultMaxKeys
	}
	return &Limiter{rule: rule, now: now, keys: map[string]*bucket{}}
}

func (l *Limiter) refilled(key string, at time.Time) *bucket {
	b, ok := l.keys[key]
	if !ok && len(l.keys) >= l.rule.MaxKeys {
		key = overflowKey
		b, ok = l.keys[key]
	}
	if !ok {
		b = &bucket{tokens: float64(l.rule.Burst), last: at}
		l.keys[key] = b
		return b
	}
	b.tokens = min(float64(l.rule.Burst), b.tokens+float64(at.Sub(b.last))/float64(l.rule.Every))
	b.last = at
	return b
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refilled(key, l.now())
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	at := l.now()
	for key, b := range l.keys {
		if b.tokens+float64(at.Sub(b.last))/float64(l.rule.Every) >= float64(l.rule.Burst) {
			delete(l.keys, key)
		}
	}
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

type All []*Limiter

func (a All) Allow(key string) bool {
	for _, l := range a {
		l.mu.Lock()
		b := l.refilled(key, l.now())
		enough := b.tokens >= 1
		l.mu.Unlock()
		if !enough {
			return false
		}
	}
	for _, l := range a {
		l.Allow(key)
	}
	return true
}
