package scan

import (
	"testing"

	"github.com/MOYARU/prs/internal/report"
)

func TestBuildChainedFindings_XSSChain(t *testing.T) {
	in := []report.Finding{
		{ID: "INPUT_REFLECTION_DETECTED"},
		{ID: "MISSING_SECURITY_HEADERS"},
		{ID: "COOKIE_HTTPONLY_FLAG_MISSING"},
	}
	out := buildChainedFindings(in)
	found := false
	for _, f := range out {
		if f.ID == "CHAIN_XSS_TO_SESSION_RISK" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected CHAIN_XSS_TO_SESSION_RISK, got %#v", out)
	}
}
