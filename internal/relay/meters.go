package relay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/store"
)

type accountMeter struct {
	month  string
	total  int64
	loaded bool
	dirty  map[string]int64
}

type meters struct {
	db       *store.DB
	now      func() time.Time
	mu       sync.Mutex
	accounts map[string]*accountMeter
}

func newMeters(db *store.DB, now func() time.Time) *meters {
	return &meters{db: db, now: now, accounts: map[string]*accountMeter{}}
}

func (m *meters) entry(accountID string) *accountMeter {
	month := m.db.Month()
	e := m.accounts[accountID]
	if e == nil {
		e = &accountMeter{dirty: map[string]int64{}}
		m.accounts[accountID] = e
	}
	if e.month != month {
		e.month = month
		e.loaded = false
		e.total = 0
	}
	if !e.loaded {
		used, err := m.db.AccountRelayBytes(context.Background(), accountID, month)
		if err != nil {
			slog.Error("load relay usage", "err", err)
		}
		e.total = used
		for _, n := range e.dirty {
			e.total += n
		}
		e.loaded = true
	}
	return e
}

func (m *meters) add(accountID, label string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entry(accountID)
	e.total += n
	e.dirty[label] += n
}

func (m *meters) over(accountID string, limit int64) bool {
	if limit <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entry(accountID).total >= limit
}

func (m *meters) flush(ctx context.Context) {
	m.mu.Lock()
	type item struct {
		label, month string
		n            int64
	}
	var items []item
	for _, e := range m.accounts {
		for label, n := range e.dirty {
			items = append(items, item{label, e.month, n})
		}
		clear(e.dirty)
	}
	m.mu.Unlock()
	for _, it := range items {
		if err := m.db.AddRelayBytes(ctx, it.label, it.month, it.n); err != nil {
			slog.Error("flush relay usage", "err", err)
		}
	}
}
