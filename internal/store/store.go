package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	keyPrefix      = "sk-gap-"
	prefixDisplay  = 12 // characters of random part shown in prefix
	bcryptCost     = 12
	randomKeyBytes = 32

	// Bound DB usage so load cannot exhaust Postgres max_connections.
	defaultMaxOpenConns = 25
	defaultMaxIdleConns = 10
	defaultConnMaxLife  = 30 * time.Minute
	defaultConnMaxIdle  = 5 * time.Minute

	// Positive cache for validated keys: avoids bcrypt+SELECT on every request.
	keyCacheTTL = 30 * time.Second
	// Throttle last_used_at writes so hot keys do not UPDATE on every RPS spike.
	lastUsedMinInterval = 60 * time.Second
	// Keep probes snappy even if the pool is busy.
	pingTimeout = 400 * time.Millisecond
	// Soft readiness: tolerate brief pool pressure after a recent successful ping.
	dbOKGrace = 45 * time.Second

	auditQueueSize   = 4096
	auditWorkers     = 2
)

// APIKey is the persisted API key record. The plaintext key is never stored.
type APIKey struct {
	ID           string     `gorm:"primaryKey;size:36" json:"id"`
	Name         string     `gorm:"size:128" json:"name"`
	KeyHash      string     `gorm:"size:128;not null" json:"-"`
	KeyLookup    string     `gorm:"size:64;uniqueIndex;not null" json:"-"` // sha256 of full key for O(1) lookup
	KeyPrefix    string     `gorm:"size:32" json:"key_prefix"`
	RateLimitRPS *float64   `json:"rate_limit_rps,omitempty"`
	Enabled      bool       `gorm:"not null;default:true" json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// AuthState stores the latest auth.json payload so token refresh survives
// restarts without a writable PVC (e.g. external Postgres only).
type AuthState struct {
	ID        string    `gorm:"primaryKey;size:32" json:"id"`
	Payload   []byte    `gorm:"not null" json:"-"`
	UpdatedAt time.Time `json:"updated_at"`
}

const AuthStateDefaultID = "default"

// AuditLog is one proxied client request for admin audit.
type AuditLog struct {
	ID               string    `gorm:"primaryKey;size:36" json:"id"`
	CreatedAt        time.Time `gorm:"index" json:"created_at"`
	RequestID        string    `gorm:"size:64;index" json:"request_id"`
	APIKeyID         string    `gorm:"size:36;index" json:"api_key_id,omitempty"`
	APIKeyName       string    `gorm:"size:128" json:"api_key_name,omitempty"`
	APIKeyPrefix     string    `gorm:"size:32" json:"api_key_prefix,omitempty"`
	Method           string    `gorm:"size:16" json:"method"`
	Path             string    `gorm:"size:512;index" json:"path"`
	Query            string    `gorm:"size:1024" json:"query,omitempty"`
	ClientIP         string    `gorm:"size:64" json:"client_ip,omitempty"`
	UserAgent        string    `gorm:"size:512" json:"user_agent,omitempty"`
	StatusCode       int       `gorm:"index" json:"status_code"`
	LatencyMS        int64     `json:"latency_ms"`
	Model            string    `gorm:"size:128;index" json:"model,omitempty"`
	Stream           bool      `json:"stream"`
	RequestBody      string    `gorm:"type:text" json:"request_body,omitempty"`
	ResponseBody     string    `gorm:"type:text" json:"response_body,omitempty"`
	RequestTruncated bool      `json:"request_truncated"`
	ResponseTruncated bool     `json:"response_truncated"`
	Error            string    `gorm:"size:1024" json:"error,omitempty"`
}

// AuditListFilter filters audit log queries.
type AuditListFilter struct {
	APIKeyID  string
	Path      string
	Model     string
	StatusMin *int
	StatusMax *int
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

// CreateKeyResult is returned once on key creation (includes plaintext).
type CreateKeyResult struct {
	Key       APIKey `json:"key"`
	Plaintext string `json:"plaintext"`
}

type keyCacheEntry struct {
	key       APIKey
	expiresAt time.Time
	lastUsed  time.Time // last time we flushed last_used_at to DB
}

// Store abstracts API key persistence.
type Store struct {
	db *gorm.DB

	cacheMu sync.RWMutex
	cache   map[string]*keyCacheEntry // lookup hash → entry

	auditCh   chan *AuditLog
	auditStop chan struct{}
	auditWG   sync.WaitGroup

	dbOKMu   sync.RWMutex
	dbLastOK time.Time
}

// Open opens a SQLite or PostgreSQL database and runs migrations.
func Open(driver, dsn string) (*Store, error) {
	var dialector gorm.Dialector
	switch strings.ToLower(driver) {
	case "sqlite":
		if dir := filepath.Dir(dsn); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("create db dir: %w", err)
			}
		}
		// Pure Go SQLite (modernc) — works with CGO_ENABLED=0.
		// Limit concurrency; sqlite dislikes many writers.
		dialector = sqlite.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported db driver %q", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("sql db: %w", err)
	}
	maxOpen := defaultMaxOpenConns
	maxIdle := defaultMaxIdleConns
	if strings.EqualFold(driver, "sqlite") {
		// Single-writer friendly defaults for local/dev.
		maxOpen = 4
		maxIdle = 2
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(defaultConnMaxLife)
	sqlDB.SetConnMaxIdleTime(defaultConnMaxIdle)

	if err := db.AutoMigrate(&APIKey{}, &AuthState{}, &AuditLog{}); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	s := &Store{
		db:        db,
		cache:     make(map[string]*keyCacheEntry),
		auditCh:   make(chan *AuditLog, auditQueueSize),
		auditStop: make(chan struct{}),
		dbLastOK:  time.Now().UTC(),
	}
	s.startAuditWorkers(auditWorkers)
	return s, nil
}

// Close stops audit workers and closes the underlying DB.
func (s *Store) Close() error {
	if s.auditStop != nil {
		close(s.auditStop)
		s.auditWG.Wait()
	}
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping checks database connectivity with a short timeout so readiness
// probes do not hang when the pool is saturated.
func (s *Store) Ping() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return err
	}
	s.dbOKMu.Lock()
	s.dbLastOK = time.Now().UTC()
	s.dbOKMu.Unlock()
	return nil
}

// Healthy reports whether the DB is currently reachable, or was recently OK
// (so brief pool saturation during load does not flap readiness).
func (s *Store) Healthy() bool {
	s.dbOKMu.RLock()
	last := s.dbLastOK
	s.dbOKMu.RUnlock()
	// Skip ping if we succeeded recently — probes must stay cheap under load.
	if !last.IsZero() && time.Since(last) < 10*time.Second {
		return true
	}
	if err := s.Ping(); err == nil {
		return true
	}
	return !last.IsZero() && time.Since(last) < dbOKGrace
}

func (s *Store) startAuditWorkers(n int) {
	if n < 1 {
		n = 1
	}
	for i := 0; i < n; i++ {
		s.auditWG.Add(1)
		go func() {
			defer s.auditWG.Done()
			for {
				select {
				case <-s.auditStop:
					// Drain remaining queued rows best-effort.
					for {
						select {
						case row := <-s.auditCh:
							_ = s.insertAuditLogSync(row)
						default:
							return
						}
					}
				case row := <-s.auditCh:
					_ = s.insertAuditLogSync(row)
				}
			}
		}()
	}
}

func (s *Store) insertAuditLogSync(row *AuditLog) error {
	if row == nil {
		return nil
	}
	if row.ID == "" {
		id, err := randomHex(16)
		if err != nil {
			return err
		}
		row.ID = id
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	return s.db.Create(row).Error
}

// CreateKey generates a new API key.
func (s *Store) CreateKey(name string, rateLimitRPS *float64) (*CreateKeyResult, error) {
	plaintext, err := generatePlaintext()
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return nil, err
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	rec := APIKey{
		ID:           id,
		Name:         name,
		KeyHash:      string(hash),
		KeyLookup:    lookupHash(plaintext),
		KeyPrefix:    displayPrefix(plaintext),
		RateLimitRPS: rateLimitRPS,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.db.Create(&rec).Error; err != nil {
		return nil, err
	}
	return &CreateKeyResult{Key: rec, Plaintext: plaintext}, nil
}

// ListKeys returns all keys (no secrets).
func (s *Store) ListKeys() ([]APIKey, error) {
	var keys []APIKey
	if err := s.db.Order("created_at desc").Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

// RevokeKey soft-disables a key by ID.
func (s *Store) RevokeKey(id string) error {
	now := time.Now().UTC()
	res := s.db.Model(&APIKey{}).Where("id = ? AND revoked_at IS NULL", id).Updates(map[string]any{
		"enabled":    false,
		"revoked_at": now,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.invalidateCacheByID(id)
	return nil
}

// ValidatePlaintext checks a bearer token against the store.
// Uses a short positive cache and async/throttled last_used_at updates so
// hot paths do not stampede Postgres under load.
func (s *Store) ValidatePlaintext(plaintext string) (*APIKey, error) {
	if plaintext == "" {
		return nil, ErrUnauthorized
	}
	lh := lookupHash(plaintext)
	now := time.Now().UTC()

	if ent := s.cacheGet(lh); ent != nil {
		rec := ent.key
		s.touchLastUsed(lh, rec.ID, now)
		out := rec
		out.LastUsedAt = &now
		return &out, nil
	}

	var rec APIKey
	err := s.db.Where("key_lookup = ? AND enabled = ? AND revoked_at IS NULL", lh, true).
		First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.KeyHash), []byte(plaintext)); err != nil {
		return nil, ErrUnauthorized
	}

	s.cachePut(lh, rec, now)
	s.touchLastUsed(lh, rec.ID, now)
	out := rec
	out.LastUsedAt = &now
	return &out, nil
}

func (s *Store) cacheGet(lookup string) *keyCacheEntry {
	s.cacheMu.RLock()
	ent, ok := s.cache[lookup]
	s.cacheMu.RUnlock()
	if !ok || ent == nil {
		return nil
	}
	if time.Now().UTC().After(ent.expiresAt) {
		s.cacheMu.Lock()
		delete(s.cache, lookup)
		s.cacheMu.Unlock()
		return nil
	}
	return ent
}

func (s *Store) cachePut(lookup string, rec APIKey, now time.Time) {
	// Do not keep bcrypt hash in long-lived structs beyond need; still needed for
	// cache-only path? We skip bcrypt on cache hit, so hash is unused after put.
	s.cacheMu.Lock()
	s.cache[lookup] = &keyCacheEntry{
		key:       rec,
		expiresAt: now.Add(keyCacheTTL),
		lastUsed:  time.Time{}, // force one async write soon
	}
	s.cacheMu.Unlock()
}

func (s *Store) invalidateCacheByID(id string) {
	s.cacheMu.Lock()
	for k, ent := range s.cache {
		if ent != nil && ent.key.ID == id {
			delete(s.cache, k)
		}
	}
	s.cacheMu.Unlock()
}

// touchLastUsed schedules a throttled async UPDATE so request path never waits on it.
func (s *Store) touchLastUsed(lookup, id string, now time.Time) {
	s.cacheMu.Lock()
	ent := s.cache[lookup]
	if ent == nil {
		s.cacheMu.Unlock()
		return
	}
	if !ent.lastUsed.IsZero() && now.Sub(ent.lastUsed) < lastUsedMinInterval {
		s.cacheMu.Unlock()
		return
	}
	ent.lastUsed = now
	s.cacheMu.Unlock()

	go func() {
		// Best-effort; ignore errors (table may be down under extreme load).
		_ = s.db.Model(&APIKey{}).Where("id = ?", id).Update("last_used_at", now).Error
	}()
}

// ErrNotFound is returned when a key id does not exist.
var ErrNotFound = errors.New("api key not found")

// ErrUnauthorized is returned when a key is invalid or revoked.
var ErrUnauthorized = errors.New("invalid api key")

// SaveAuthState upserts the full auth.json payload.
func (s *Store) SaveAuthState(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("empty auth payload")
	}
	rec := AuthState{
		ID:        AuthStateDefaultID,
		Payload:   payload,
		UpdatedAt: time.Now().UTC(),
	}
	return s.db.Save(&rec).Error
}

// LoadAuthState returns the stored auth.json payload, or nil if missing.
func (s *Store) LoadAuthState() ([]byte, time.Time, error) {
	var rec AuthState
	err := s.db.First(&rec, "id = ?", AuthStateDefaultID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	return rec.Payload, rec.UpdatedAt, nil
}

// InsertAuditLog persists one audit row.
// InsertAuditLog enqueues a row for background writers.
// Non-blocking: if the queue is full the event is dropped so request path
// never waits on Postgres under load.
func (s *Store) InsertAuditLog(row *AuditLog) error {
	if row == nil {
		return errors.New("nil audit log")
	}
	if row.ID == "" {
		id, err := randomHex(16)
		if err != nil {
			return err
		}
		row.ID = id
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	if s.auditCh == nil {
		// Tests / early paths without workers: write sync.
		return s.insertAuditLogSync(row)
	}
	select {
	case s.auditCh <- row:
		return nil
	default:
		// Drop rather than block the proxy.
		return nil
	}
}

// GetAuditLog returns one audit entry by id.
func (s *Store) GetAuditLog(id string) (*AuditLog, error) {
	var rec AuditLog
	err := s.db.First(&rec, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListAuditLogs returns audit rows matching filter (newest first).
func (s *Store) ListAuditLogs(f AuditListFilter) ([]AuditLog, int64, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	q := s.db.Model(&AuditLog{})
	if f.APIKeyID != "" {
		q = q.Where("api_key_id = ?", f.APIKeyID)
	}
	if f.Path != "" {
		q = q.Where("path = ?", f.Path)
	}
	if f.Model != "" {
		q = q.Where("model = ?", f.Model)
	}
	if f.StatusMin != nil {
		q = q.Where("status_code >= ?", *f.StatusMin)
	}
	if f.StatusMax != nil {
		q = q.Where("status_code <= ?", *f.StatusMax)
	}
	if f.From != nil {
		q = q.Where("created_at >= ?", *f.From)
	}
	if f.To != nil {
		q = q.Where("created_at <= ?", *f.To)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []AuditLog
	if err := q.Order("created_at desc").Limit(f.Limit).Offset(f.Offset).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

func generatePlaintext() (string, error) {
	b, err := randomHex(randomKeyBytes)
	if err != nil {
		return "", err
	}
	return keyPrefix + b, nil
}

func displayPrefix(plaintext string) string {
	// sk-gap- + first N hex chars
	if len(plaintext) < len(keyPrefix)+prefixDisplay {
		return plaintext
	}
	return plaintext[:len(keyPrefix)+prefixDisplay] + "…"
}

func lookupHash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
