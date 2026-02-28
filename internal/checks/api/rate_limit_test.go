package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
)

func TestRateLimitPassiveHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/api/users")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()

	u, _ := url.Parse(srv.URL + "/api/users")
	scanCtx := &ctxpkg.Context{
		RequestContext: context.Background(),
		Mode:           ctxpkg.Passive,
		FinalURL:       u,
		Response:       resp,
		HTTPClient:     srv.Client(),
	}

	findings, err := CheckRateLimitAbsencePassive(scanCtx)
	if err != nil {
		t.Fatalf("CheckRateLimitAbsencePassive() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected passive findings, got none")
	}
}
