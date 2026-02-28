package injection

import (
	"net/http"
	"net/url"
	"testing"

	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
)

func newDOMCtx(t *testing.T, target string, contentType string, body string) *ctxpkg.Context {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}
	return &ctxpkg.Context{
		FinalURL: u,
		Response: &http.Response{
			Header: http.Header{
				"Content-Type": []string{contentType},
			},
		},
		BodyBytes: []byte(body),
	}
}

func TestCheckDOMXSSPassiveDetectsFlow(t *testing.T) {
	body := `<html><body><script>document.getElementById("out").innerHTML = location.hash;</script></body></html>`
	ctx := newDOMCtx(t, "https://example.com", "text/html", body)
	findings, err := CheckDOMXSSPassive(ctx)
	if err != nil {
		t.Fatalf("CheckDOMXSSPassive() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected DOM_XSS_POSSIBLE finding")
	}
	if findings[0].ID != "DOM_XSS_POSSIBLE" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestCheckDOMXSSPassiveDetectsRiskyCombo(t *testing.T) {
	body := `<html><body><script>var q = location.search; setTimeout("doWork()", 1000);</script></body></html>`
	ctx := newDOMCtx(t, "https://example.com", "text/html", body)
	findings, err := CheckDOMXSSPassive(ctx)
	if err != nil {
		t.Fatalf("CheckDOMXSSPassive() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected DOM_XSS_RISKY_SOURCE_SINK finding")
	}
	if findings[0].ID != "DOM_XSS_RISKY_SOURCE_SINK" {
		t.Fatalf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestCheckDOMXSSPassiveSkipsSafeTextContent(t *testing.T) {
	body := `<html><body><script>const q = location.search; document.getElementById("x").textContent = q;</script></body></html>`
	ctx := newDOMCtx(t, "https://example.com", "text/html", body)
	findings, err := CheckDOMXSSPassive(ctx)
	if err != nil {
		t.Fatalf("CheckDOMXSSPassive() error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
