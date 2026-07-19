package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCreateValidateRevoke(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	res, err := s.CreateKey("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Plaintext == "" || res.Key.ID == "" {
		t.Fatal("missing plaintext or id")
	}
	if res.Key.KeyPrefix == "" {
		t.Fatal("expected key prefix")
	}

	got, err := s.ValidatePlaintext(res.Plaintext)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.ID != res.Key.ID {
		t.Fatalf("id mismatch")
	}

	// Cache hit path (no second DB round-trip required for success).
	got2, err := s.ValidatePlaintext(res.Plaintext)
	if err != nil {
		t.Fatalf("validate cached: %v", err)
	}
	if got2.ID != res.Key.ID {
		t.Fatalf("cached id mismatch")
	}

	if _, err := s.ValidatePlaintext("sk-gap-invalid"); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}

	if err := s.RevokeKey(res.Key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidatePlaintext(res.Plaintext); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized after revoke, got %v", err)
	}

	keys, err := s.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Enabled {
		t.Fatalf("list after revoke: %+v", keys)
	}
}

func TestRevokeNotFound(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RevokeKey("does-not-exist"); err != ErrNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestAuthStateAndAudit(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	payload := []byte(`{"k":{"key":"x","refresh_token":"r"}}`)
	if err := s.SaveAuthState(payload); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.LoadAuthState()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("auth state mismatch: %s", got)
	}

	row := &AuditLog{
		RequestID:  "req-1",
		Method:     "POST",
		Path:       "/v1/chat/completions",
		StatusCode: 200,
		Model:      "grok-4.5",
		RequestBody: `{"model":"grok-4.5"}`,
		ResponseBody: `{"ok":true}`,
	}
	if err := s.InsertAuditLog(row); err != nil {
		t.Fatal(err)
	}
	if row.ID == "" {
		t.Fatal("expected id")
	}
	// Workers write async; wait briefly.
	var one *AuditLog
	var getErr error
	for i := 0; i < 50; i++ {
		one, getErr = s.GetAuditLog(row.ID)
		if getErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	if one.Model != "grok-4.5" {
		t.Fatalf("model=%s", one.Model)
	}
	list, total, err := s.ListAuditLogs(AuditListFilter{Path: "/v1/chat/completions", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 {
		t.Fatalf("list total=%d len=%d", total, len(list))
	}
	if _, err := s.GetAuditLog("missing"); err != ErrNotFound {
		t.Fatalf("got %v", err)
	}
}
