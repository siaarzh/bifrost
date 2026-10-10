package logstore

import (
	"context"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/gorm"
)

// MaintenanceGate is implemented by stores that can tell whether another node
// is currently running logstore schema migrations. Background writers consult
// it before touching the logs table so their statements do not queue behind a
// pending ALTER TABLE and turn one node's rollout into a cluster-wide stall.
//
// It is deliberately NOT part of LogStore: callers type-assert for it, so a
// store (or a test double embedding LogStore) that lacks it simply has no gate
// and behaves exactly as before.
type MaintenanceGate interface {
	// MigrationInProgress reports whether the migration advisory lock is held
	// by some session. It never blocks for long and fails open: any error,
	// timeout, or non-Postgres dialect reports false.
	MigrationInProgress(ctx context.Context) bool
}

const (
	// maintenanceCheckTTL is how long one pg_locks answer is reused. Every
	// caller in the process (batch writer, cleanup ticks, deferred-usage
	// goroutines, matview refresher) shares a probe, so the DB sees at most one
	// probe query per TTL per process regardless of how many callers poll.
	maintenanceCheckTTL = time.Second
	// maintenanceCheckTimeout bounds the probe query itself so a hung database
	// cannot stall the goroutine that asked; a timeout reports "not migrating".
	maintenanceCheckTimeout = 2 * time.Second
)

// migrationLockProbe answers MigrationInProgress for one *gorm.DB with a short
// cache. It reads pg_locks, which is a side-effect-free view readable by every
// role; calling pg_try_advisory_lock here would steal the lock from the
// migrator, so the probe never touches the lock itself.
type migrationLockProbe struct {
	db     *gorm.DB
	logger schemas.Logger
	// now is swapped by tests to drive the cache deterministically.
	now func() time.Time

	mu        sync.Mutex
	checkedAt time.Time
	held      bool
	errLogged bool
}

func newMigrationLockProbe(db *gorm.DB, logger schemas.Logger) *migrationLockProbe {
	return &migrationLockProbe{db: db, logger: logger, now: time.Now}
}

// migrationLockHeldQuery finds a granted session advisory lock for a 64-bit
// key in the current database. Postgres stores a bigint advisory key as
// classid = high 32 bits and objid = low 32 bits, with objsubid = 1.
const migrationLockHeldQuery = `
SELECT EXISTS (
	SELECT 1
	FROM pg_locks
	WHERE locktype = 'advisory'
	  AND granted
	  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
	  AND classid = ?
	  AND objid = ?
	  AND objsubid = 1
)`

// advisoryKeyHalves splits a bigint advisory lock key the way pg_locks reports
// it (classid, objid), so the probe stays correct if the key constant changes.
func advisoryKeyHalves(key int64) (classid, objid int64) {
	u := uint64(key)
	return int64(u >> 32), int64(u & 0xffffffff)
}

// inProgress reports whether the migration lock is held, reusing the last
// answer for maintenanceCheckTTL. The mutex is held across the query so that
// concurrent callers wait for one round trip instead of issuing their own.
func (p *migrationLockProbe) inProgress(ctx context.Context) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !p.checkedAt.IsZero() && now.Sub(p.checkedAt) < maintenanceCheckTTL {
		return p.held
	}
	if p.db == nil || p.db.Dialector.Name() != "postgres" {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	queryCtx, cancel := context.WithTimeout(ctx, maintenanceCheckTimeout)
	defer cancel()
	classid, objid := advisoryKeyHalves(migrationAdvisoryLockKey)
	var held bool
	err := p.db.WithContext(queryCtx).Raw(migrationLockHeldQuery, classid, objid).Scan(&held).Error
	p.checkedAt = now
	if err != nil {
		// Fail open: a probe that cannot reach the database must not look like
		// a migration, or an outage would silently hoard writes in memory
		// instead of taking the existing retry/drop path.
		p.held = false
		if !p.errLogged && p.logger != nil {
			p.logger.Debug("[logstore] migration lock probe failed, assuming no migration: %v", err)
			p.errLogged = true
		}
		return false
	}
	p.errLogged = false
	p.held = held
	return held
}

// migrationProbe returns the store's shared probe, creating it on first use so
// every construction path of RDBLogStore (Postgres, SQLite, the ClickHouse
// embed) gets one without touching each constructor.
func (s *RDBLogStore) migrationProbe() *migrationLockProbe {
	s.migrationProbeOnce.Do(func() {
		s.migrationProbeInst = newMigrationLockProbe(s.db, s.logger)
	})
	return s.migrationProbeInst
}

// MigrationInProgress implements MaintenanceGate.
func (s *RDBLogStore) MigrationInProgress(ctx context.Context) bool {
	return s.migrationProbe().inProgress(ctx)
}

// MigrationInProgress implements MaintenanceGate by forwarding to the inner
// store when it has a gate; a wrapped store without one reports false.
func (h *HybridLogStore) MigrationInProgress(ctx context.Context) bool {
	gate, ok := h.inner.(MaintenanceGate)
	return ok && gate.MigrationInProgress(ctx)
}

// MigrationInProgressFor is the type-asserting helper callers use so a store
// without a gate reads as "not migrating".
func MigrationInProgressFor(ctx context.Context, store any) bool {
	gate, ok := store.(MaintenanceGate)
	return ok && gate.MigrationInProgress(ctx)
}
