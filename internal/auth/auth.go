package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// Entry is a single credential block from auth.json.
// Grok CLI uses oidc_client_id / oidc_issuer; older/sample files may use client_id / issuer.
type Entry struct {
	Key          string    `json:"key"`
	AuthMode     string    `json:"auth_mode"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id,omitempty"`
	OIDCClientID string    `json:"oidc_client_id,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	OIDCIssuer   string    `json:"oidc_issuer,omitempty"`
}

// resolvedClientID prefers explicit client_id, then Grok CLI oidc_client_id.
func (e Entry) resolvedClientID() string {
	return firstNonEmpty(e.ClientID, e.OIDCClientID)
}

// resolvedIssuer prefers explicit issuer, then Grok CLI oidc_issuer.
func (e Entry) resolvedIssuer() string {
	return firstNonEmpty(e.Issuer, e.OIDCIssuer)
}

// FileData is the top-level map structure of auth.json.
type FileData map[string]Entry

// PersistFunc is called after a successful token refresh with the full auth map.
// Use it to store credentials in an external DB when the auth file is read-only.
type PersistFunc func(data FileData) error

// Manager loads, refreshes, and watches Grok auth.json credentials.
type Manager struct {
	path         string
	issuer       string
	clientID     string
	account      string
	refreshSkew  time.Duration
	httpClient   *http.Client
	log          *zap.Logger
	persist      PersistFunc
	fileWritable bool // false for read-only secret mounts; DB Persist is enough

	mu            sync.RWMutex
	mapKey        string
	entry         Entry
	fileData      FileData
	tokenEndpoint string
	writing       bool // skip fsnotify events from our own writes

	watcher *fsnotify.Watcher
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// Options configures a Manager.
type Options struct {
	Path        string
	Issuer      string
	ClientID    string
	Account     string
	RefreshSkew time.Duration
	HTTPClient  *http.Client
	Log         *zap.Logger
	// Persist is optional; invoked after refresh (e.g. save to Postgres).
	// When set and the auth file is read-only (K8s Secret), file write-back is skipped.
	Persist PersistFunc
	// InitialData, if non-empty, is loaded instead of reading Path first
	// (e.g. auth blob restored from Postgres).
	InitialData []byte
}

// NewManager creates a Manager and loads credentials from disk.
func NewManager(opts Options) (*Manager, error) {
	if opts.Path == "" {
		return nil, errors.New("auth file path is required")
	}
	if opts.RefreshSkew <= 0 {
		opts.RefreshSkew = 5 * time.Minute
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.Log == nil {
		opts.Log = zap.NewNop()
	}
	if opts.Issuer == "" {
		opts.Issuer = "https://auth.x.ai"
	}

	writable := authPathWritable(opts.Path)
	m := &Manager{
		path:         opts.Path,
		issuer:       strings.TrimRight(opts.Issuer, "/"),
		clientID:     opts.ClientID,
		account:      opts.Account,
		refreshSkew:  opts.RefreshSkew,
		httpClient:   opts.HTTPClient,
		log:          opts.Log,
		persist:      opts.Persist,
		fileWritable: writable,
		stopCh:       make(chan struct{}),
	}
	if !writable {
		m.log.Info("auth file is not writable; refresh will use Persist only (no file write-back)",
			zap.String("path", opts.Path))
	}

	if len(opts.InitialData) > 0 {
		if err := m.loadBytes(opts.InitialData); err != nil {
			return nil, err
		}
		// Only materialize to disk when the path is writable (local/dev).
		if m.fileWritable {
			if err := writeAuthFileAtomic(m.path, m.fileData); err != nil {
				m.log.Debug("could not write initial auth data to file", zap.Error(err))
			}
		}
	} else if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// StartWatch begins watching auth.json for external changes.
func (m *Manager) StartWatch() error {
	dir := filepath.Dir(m.path)
	if dir == "" || dir == "." {
		abs, err := filepath.Abs(m.path)
		if err != nil {
			return err
		}
		dir = filepath.Dir(abs)
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return fmt.Errorf("watch dir %s: %w", dir, err)
	}
	m.watcher = w

	m.wg.Add(1)
	go m.watchLoop()
	return nil
}

// Close stops the file watcher.
func (m *Manager) Close() error {
	close(m.stopCh)
	if m.watcher != nil {
		_ = m.watcher.Close()
	}
	m.wg.Wait()
	return nil
}

func (m *Manager) watchLoop() {
	defer m.wg.Done()
	base := filepath.Base(m.path)
	var debounce *time.Timer

	for {
		select {
		case <-m.stopCh:
			if debounce != nil {
				debounce.Stop()
			}
			return
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.log.Warn("auth file watch error", zap.Error(err))
		case ev, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != base {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			m.mu.RLock()
			skip := m.writing
			m.mu.RUnlock()
			if skip {
				continue
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(200*time.Millisecond, func() {
				if err := m.Reload(); err != nil {
					m.log.Warn("reload auth.json after change failed", zap.Error(err))
				} else {
					m.log.Info("auth.json reloaded from disk")
				}
			})
		}
	}
}

// Reload re-reads auth.json from disk.
func (m *Manager) Reload() error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read auth file: %w", err)
	}
	return m.loadBytes(data)
}

func (m *Manager) loadBytes(data []byte) error {
	var fd FileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return fmt.Errorf("parse auth file: %w", err)
	}
	if len(fd) == 0 {
		return errors.New("auth file has no entries")
	}

	mapKey, entry, err := selectEntry(fd, m.account)
	if err != nil {
		return err
	}
	if strings.TrimSpace(entry.Key) == "" {
		return errors.New("selected auth entry has empty key")
	}

	m.mu.Lock()
	m.fileData = fd
	m.mapKey = mapKey
	m.entry = entry
	m.tokenEndpoint = "" // re-discover if issuer changed
	m.mu.Unlock()

	m.log.Info("auth loaded",
		zap.String("map_key", redactMapKey(mapKey)),
		zap.Time("expires_at", entry.ExpiresAt),
		zap.String("auth_mode", entry.AuthMode),
	)
	return nil
}

func selectEntry(fd FileData, account string) (string, Entry, error) {
	if account != "" {
		for k, e := range fd {
			if k == account || strings.Contains(k, account) {
				return k, e, nil
			}
		}
		return "", Entry{}, fmt.Errorf("auth account %q not found", account)
	}
	// Prefer first entry with a non-empty key; stable-ish by iterating map
	// (order not guaranteed — pick one with longest remaining lifetime if multiple).
	var bestKey string
	var best Entry
	var found bool
	for k, e := range fd {
		if strings.TrimSpace(e.Key) == "" {
			continue
		}
		if !found || e.ExpiresAt.After(best.ExpiresAt) {
			bestKey = k
			best = e
			found = true
		}
	}
	if !found {
		return "", Entry{}, errors.New("no usable auth entry found")
	}
	return bestKey, best, nil
}

// Ready reports whether a non-empty access token is loaded.
func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return strings.TrimSpace(m.entry.Key) != ""
}

// ExpiresAt returns the current token expiry (zero if unknown).
func (m *Manager) ExpiresAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entry.ExpiresAt
}

// GetAccessToken returns a valid access token, refreshing if needed.
func (m *Manager) GetAccessToken(ctx context.Context) (string, error) {
	m.mu.RLock()
	entry := m.entry
	skew := m.refreshSkew
	m.mu.RUnlock()

	if strings.TrimSpace(entry.Key) == "" {
		return "", errors.New("no access token available")
	}

	needsRefresh := !entry.ExpiresAt.IsZero() && time.Now().Add(skew).After(entry.ExpiresAt)
	if needsRefresh {
		if err := m.Refresh(ctx); err != nil {
			// If still not expired, serve current token
			if time.Now().Before(entry.ExpiresAt) {
				m.log.Warn("token refresh failed; using existing token until expiry", zap.Error(err))
				return entry.Key, nil
			}
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}
		m.mu.RLock()
		entry = m.entry
		m.mu.RUnlock()
	}
	return entry.Key, nil
}

// ForceRefresh refreshes regardless of expiry (e.g. after upstream 401).
func (m *Manager) ForceRefresh(ctx context.Context) error {
	return m.Refresh(ctx)
}

// Refresh exchanges the refresh_token for a new access token.
func (m *Manager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	// Serialize refreshes
	entry := m.entry
	mapKey := m.mapKey
	clientID := firstNonEmpty(entry.resolvedClientID(), m.clientID)
	issuer := firstNonEmpty(entry.resolvedIssuer(), m.issuer)
	m.mu.Unlock()

	if strings.TrimSpace(entry.RefreshToken) == "" {
		return errors.New("no refresh_token available")
	}
	if clientID == "" {
		// xAI requires client_id; Grok CLI stores it as oidc_client_id.
		m.log.Debug("refresh without client_id (not set in auth entry or config)")
	}

	tokenURL, err := m.discoverTokenEndpoint(ctx, issuer)
	if err != nil {
		return err
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", entry.RefreshToken)
	if clientID != "" {
		form.Set("client_id", clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token refresh request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("token refresh failed: status %d: %s", resp.StatusCode, sanitizeErrBody(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return errors.New("token response missing access_token")
	}

	newEntry := entry
	newEntry.Key = tr.AccessToken
	if tr.RefreshToken != "" {
		newEntry.RefreshToken = tr.RefreshToken
	}
	if tr.ExpiresIn > 0 {
		newEntry.ExpiresAt = time.Now().UTC().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		// Fallback: 1 hour if provider omitted expires_in
		newEntry.ExpiresAt = time.Now().UTC().Add(time.Hour)
	}

	m.mu.Lock()
	m.entry = newEntry
	if m.fileData == nil {
		m.fileData = FileData{}
	}
	m.fileData[mapKey] = newEntry
	fdCopy := cloneFileData(m.fileData)
	m.writing = true
	m.mu.Unlock()

	if m.persist != nil {
		if err := m.persist(fdCopy); err != nil {
			m.log.Warn("failed to persist refreshed auth to store", zap.Error(err))
		}
	}

	// K8s Secret mounts are read-only: never attempt atomic write there.
	// Source of truth with Persist is the database (auth_states).
	if m.fileWritable {
		if err := writeAuthFileAtomic(m.path, fdCopy); err != nil {
			m.mu.Lock()
			m.writing = false
			m.mu.Unlock()
			m.log.Warn("failed to write refreshed auth.json", zap.Error(err))
			m.log.Info("access token refreshed", zap.Time("expires_at", newEntry.ExpiresAt))
			return nil
		}
		// Brief delay so fsnotify can see our write and we ignore it
		time.AfterFunc(500*time.Millisecond, func() {
			m.mu.Lock()
			m.writing = false
			m.mu.Unlock()
		})
	} else {
		m.mu.Lock()
		m.writing = false
		m.mu.Unlock()
	}

	m.log.Info("access token refreshed", zap.Time("expires_at", newEntry.ExpiresAt))
	return nil
}

// authPathWritable reports whether atomic write-back of path is possible.
// K8s Secret subPath mounts are typically read-only files (parent dir may still be RW).
func authPathWritable(path string) bool {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".auth-writetest-*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(name)

	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return false
		}
		_ = f.Close()
	}
	return true
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type oidcDiscovery struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func (m *Manager) discoverTokenEndpoint(ctx context.Context, issuer string) (string, error) {
	m.mu.RLock()
	cached := m.tokenEndpoint
	m.mu.RUnlock()
	if cached != "" {
		return cached, nil
	}

	discURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		// Fallback: common OIDC token path
		fallback := strings.TrimRight(issuer, "/") + "/oauth/token"
		m.log.Warn("OIDC discovery failed; using fallback token endpoint",
			zap.Error(err), zap.String("fallback", fallback))
		m.mu.Lock()
		m.tokenEndpoint = fallback
		m.mu.Unlock()
		return fallback, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		fallback := strings.TrimRight(issuer, "/") + "/oauth/token"
		m.log.Warn("OIDC discovery non-200; using fallback",
			zap.Int("status", resp.StatusCode), zap.String("fallback", fallback))
		m.mu.Lock()
		m.tokenEndpoint = fallback
		m.mu.Unlock()
		return fallback, nil
	}
	var disc oidcDiscovery
	if err := json.Unmarshal(body, &disc); err != nil || disc.TokenEndpoint == "" {
		fallback := strings.TrimRight(issuer, "/") + "/oauth/token"
		m.mu.Lock()
		m.tokenEndpoint = fallback
		m.mu.Unlock()
		return fallback, nil
	}
	m.mu.Lock()
	m.tokenEndpoint = disc.TokenEndpoint
	m.mu.Unlock()
	return disc.TokenEndpoint, nil
}

func writeAuthFileAtomic(path string, data FileData) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".auth-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func cloneFileData(src FileData) FileData {
	out := make(FileData, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func redactMapKey(k string) string {
	if len(k) <= 24 {
		return k
	}
	return k[:20] + "…"
}

func sanitizeErrBody(b []byte) string {
	s := string(bytes.TrimSpace(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	// Avoid echoing tokens if provider accidentally returns them
	if strings.Contains(strings.ToLower(s), "access_token") {
		return "(redacted error body)"
	}
	return s
}

// ParseFile is exported for tests.
func ParseFile(data []byte) (FileData, error) {
	var fd FileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return nil, err
	}
	return fd, nil
}
