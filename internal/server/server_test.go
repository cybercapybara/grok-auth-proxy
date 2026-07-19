package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/cybercapybara/grok-auth-proxy/internal/auth"
	"github.com/cybercapybara/grok-auth-proxy/internal/config"
	"github.com/cybercapybara/grok-auth-proxy/internal/server"
	"github.com/cybercapybara/grok-auth-proxy/internal/store"
)

func TestE2EAdminAndProxy(t *testing.T) {
	// Mock upstream xAI
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"grok-4.5"}]}`))
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()

	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	authJSON := `{
		"https://auth.x.ai::test": {
			"key": "test-jwt",
			"auth_mode": "oidc",
			"refresh_token": "ref",
			"expires_at": "2099-01-01T00:00:00Z"
		}
	}`
	if err := os.WriteFile(authPath, []byte(authJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open("sqlite", filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	authMgr, err := auth.NewManager(auth.Options{
		Path:        authPath,
		RefreshSkew: time.Minute,
		Log:         zap.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Addr:            ":0",
			AdminKey:        "admin-secret",
			ShutdownTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			File:         authPath,
			UpstreamBase: up.URL + "/v1",
			RefreshSkew:  time.Minute,
		},
		DB:        config.DBConfig{Driver: "sqlite", DSN: filepath.Join(dir, "db.sqlite")},
		RateLimit: config.RateLimitConfig{RPS: 100, Burst: 100},
		CORS:      config.CORSConfig{AllowedOrigins: []string{"*"}},
		Log:       config.LogConfig{Level: "error", Redact: true},
		Metrics:   config.MetricsConfig{Enabled: false, Path: "/metrics"},
		Audit:     config.AuditConfig{Enabled: true, MaxBodyBytes: 65536},
	}

	srv, err := server.New(server.Dependencies{
		Config: cfg,
		Log:    zap.NewNop(),
		Auth:   authMgr,
		Store:  st,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := srv.Engine()

	// Health
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != 200 {
		t.Fatalf("health=%d", w.Code)
	}

	// Ready
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if w.Code != 200 {
		t.Fatalf("ready=%d %s", w.Code, w.Body.String())
	}

	// Create API key
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/keys", bytes.NewReader([]byte(`{"name":"e2e"}`)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create key=%d %s", w.Code, w.Body.String())
	}
	var created struct {
		Key string `json:"key"`
		ID  string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Key == "" {
		t.Fatal("missing plaintext key")
	}

	// List keys
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("X-Admin-Key", "admin-secret")
	engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list=%d", w.Code)
	}

	// Models via proxy
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+created.Key)
	engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("models=%d %s", w.Code, w.Body.String())
	}
	body, _ := io.ReadAll(w.Body)
	if !bytes.Contains(body, []byte("grok-4.5")) {
		t.Fatalf("models body=%s", body)
	}

	// Chat completions
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(
		`{"model":"grok-4.5","messages":[{"role":"user","content":"hi"}]}`,
	)))
	req.Header.Set("Authorization", "Bearer "+created.Key)
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("chat=%d %s", w.Code, w.Body.String())
	}

	// Audit is written asynchronously
	deadline := time.Now().Add(2 * time.Second)
	var auditList struct {
		Total int `json:"total"`
		Items []struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Path  string `json:"path"`
		} `json:"items"`
	}
	for {
		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/admin/audit?path=/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer admin-secret")
		engine.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("audit list=%d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &auditList); err != nil {
			t.Fatal(err)
		}
		if auditList.Total >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for audit log")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if auditList.Items[0].Model != "grok-4.5" {
		t.Fatalf("audit model=%s", auditList.Items[0].Model)
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/audit/"+auditList.Items[0].ID, nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit get=%d %s", w.Code, w.Body.String())
	}

	// Unauthorized without key
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// Revoke
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/admin/keys/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("revoke=%d %s", w.Code, w.Body.String())
	}

	// Key no longer works
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+created.Key)
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d", w.Code)
	}
}
