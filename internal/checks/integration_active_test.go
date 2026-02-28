package checks_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MOYARU/prs/internal/checks/api"
	"github.com/MOYARU/prs/internal/checks/application"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/input"
	"github.com/MOYARU/prs/internal/checks/network"
	"github.com/MOYARU/prs/internal/checks/ssrf"
	"github.com/MOYARU/prs/internal/report"
)

func TestActive_MethodOverride_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.EqualFold(r.Header.Get("X-HTTP-Method-Override"), "DELETE") {
			w.WriteHeader(http.StatusAccepted) // 202
			return
		}
		w.WriteHeader(http.StatusForbidden) // 403 baseline
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	scanCtx := &ctxpkg.Context{
		RequestContext: context.Background(),
		Mode:           ctxpkg.Active,
		FinalURL:       u,
		HTTPClient:     srv.Client(),
	}

	findings, err := api.CheckMethodOverride(scanCtx)
	if err != nil {
		t.Fatalf("CheckMethodOverride() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected finding, got none")
	}
	found := false
	for _, f := range findings {
		if f.ID == "METHOD_OVERRIDE_ALLOWED" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected METHOD_OVERRIDE_ALLOWED finding, got: %#v", findings)
	}
}

func TestActive_CORSOriginReflection_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin) // reflect origin
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := srv.Client()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("baseline GET error: %v", err)
	}
	defer resp.Body.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	scanCtx := &ctxpkg.Context{
		RequestContext: context.Background(),
		Mode:           ctxpkg.Active,
		FinalURL:       u,
		Response:       resp,
		HTTPClient:     client,
	}

	findings, err := network.CheckCORSConfiguration(scanCtx)
	if err != nil {
		t.Fatalf("CheckCORSConfiguration() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected finding, got none")
	}
	found := false
	for _, f := range findings {
		if f.ID == "CORS_ORIGIN_REFLECTION" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected CORS_ORIGIN_REFLECTION finding, got: %#v", findings)
	}
}

func TestActive_ParameterPollution_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()["id"]
		if len(values) > 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("polluted_value accepted"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("normal response"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL + "?id=1")
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	scanCtx := &ctxpkg.Context{
		RequestContext: context.Background(),
		Mode:           ctxpkg.Active,
		FinalURL:       u,
		HTTPClient:     srv.Client(),
	}

	findings, err := input.CheckParameterPollution(scanCtx)
	if err != nil {
		t.Fatalf("CheckParameterPollution() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected finding, got none")
	}
	found := false
	for _, f := range findings {
		if f.ID == "PARAMETER_POLLUTION_DETECTED" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected PARAMETER_POLLUTION_DETECTED finding, got: %#v", findings)
	}
}

func TestActive_SSRF_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injected := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		l := strings.ToLower(injected)
		switch {
		case strings.Contains(l, "example.com"):
			_, _ = w.Write([]byte("<h1>Example Domain</h1> this domain is for use in documentation iana.org/domains/example"))
		case strings.Contains(l, "127.0.0.1:6379"):
			_, _ = w.Write([]byte("redis service banner"))
		default:
			_, _ = w.Write([]byte("baseline response"))
		}
	}))
	defer srv.Close()

	target := srv.URL + "?url=http://safe.local/resource"
	resp, err := srv.Client().Get(target)
	if err != nil {
		t.Fatalf("baseline GET error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	resp.Body.Close()

	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	scanCtx := &ctxpkg.Context{
		RequestContext: context.Background(),
		Mode:           ctxpkg.Active,
		FinalURL:       u,
		Response:       resp,
		BodyBytes:      body,
		HTTPClient:     srv.Client(),
	}

	findings, err := ssrf.CheckSSRF(scanCtx)
	if err != nil {
		t.Fatalf("CheckSSRF() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected SSRF finding, got none")
	}

	if !hasFindingID(findings, "SSRF_CALLBACK_DETECTED") && !hasFindingID(findings, "SSRF_LOCAL_ACCESS_DETECTED") {
		t.Fatalf("expected SSRF_* finding, got: %#v", findings)
	}
}

func TestActive_IDOR_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/profile/1":
			_, _ = w.Write([]byte(`{"user_id":"1","email":"u1@example.com","role":"user"}`))
		case "/profile/2":
			_, _ = w.Write([]byte(`{"user_id":"2","email":"u2@example.com","role":"user"}`))
		case "/profile/3":
			_, _ = w.Write([]byte(`{"user_id":"3","email":"u3@example.com","role":"admin"}`))
		default:
			_, _ = w.Write([]byte(`{"user_id":"0","role":"guest"}`))
		}
	}))
	defer srv.Close()

	target := srv.URL + "/profile/2"
	resp, err := srv.Client().Get(target)
	if err != nil {
		t.Fatalf("baseline GET error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	resp.Body.Close()

	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	scanCtx := &ctxpkg.Context{
		RequestContext: context.Background(),
		Mode:           ctxpkg.Active,
		FinalURL:       u,
		Response:       resp,
		BodyBytes:      body,
		HTTPClient:     srv.Client(),
	}

	findings, err := application.CheckIDORActive(scanCtx)
	if err != nil {
		t.Fatalf("CheckIDORActive() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected IDOR finding, got none")
	}
	if !hasFindingID(findings, "IDOR_POSSIBLE") && !hasFindingID(findings, "IDOR_RESOURCE_GUESSING") {
		t.Fatalf("expected IDOR finding, got: %#v", findings)
	}
}

func hasFindingID(findings []report.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}
