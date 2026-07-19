package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Store abstracts API key persistence.
type Store struct {
	db *gorm.DB
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
	if err := db.AutoMigrate(&APIKey{}, &AuthState{}, &AuditLog{}); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying DB.
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping checks database connectivity.
func (s *Store) Ping() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
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
	return nil
}

// ValidatePlaintext checks a bearer token against the store.
// Returns the key record if valid.
func (s *Store) ValidatePlaintext(plaintext string) (*APIKey, error) {
	if plaintext == "" {
		return nil, ErrUnauthorized
	}
	var rec APIKey
	err := s.db.Where("key_lookup = ? AND enabled = ? AND revoked_at IS NULL", lookupHash(plaintext), true).
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
	now := time.Now().UTC()
	_ = s.db.Model(&APIKey{}).Where("id = ?", rec.ID).Update("last_used_at", now).Error
	rec.LastUsedAt = &now
	return &rec, nil
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
	return s.db.Create(row).Error
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
