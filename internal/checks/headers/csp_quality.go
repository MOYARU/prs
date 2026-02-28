package headers

import (
	"fmt"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

// CheckCSPQualityPassive scores CSP policy quality beyond presence/absence.
func CheckCSPQualityPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Response == nil {
		return findings, nil
	}

	csp := ctx.Response.Header.Get("Content-Security-Policy")
	if csp == "" {
		return findings, nil
	}

	policy := strings.ToLower(csp)
	score := 100
	issues := make([]string, 0, 6)

	if strings.Contains(policy, "'unsafe-inline'") {
		score -= 35
		issues = append(issues, "unsafe-inline")
	}
	if strings.Contains(policy, "'unsafe-eval'") {
		score -= 25
		issues = append(issues, "unsafe-eval")
	}
	if strings.Contains(policy, "script-src *") || strings.Contains(policy, "default-src *") {
		score -= 30
		issues = append(issues, "wildcard-script/default-src")
	}
	if !strings.Contains(policy, "object-src") {
		score -= 10
		issues = append(issues, "missing-object-src")
	}
	if !strings.Contains(policy, "base-uri") {
		score -= 10
		issues = append(issues, "missing-base-uri")
	}

	if score < 0 {
		score = 0
	}
	if score >= 80 {
		return findings, nil
	}

	sev := report.SeverityLow
	conf := report.ConfidenceMedium
	if score < 50 {
		sev = report.SeverityMedium
	}

	findings = append(findings, report.Finding{
		ID:                         "CSP_POLICY_WEAK",
		Category:                   string(checks.CategorySecurityHeaders),
		Severity:                   sev,
		Confidence:                 conf,
		Title:                      "Weak Content Security Policy Quality",
		Message:                    "CSP is present but policy quality is weak enough to leave XSS/script injection exposure windows.",
		Evidence:                   fmt.Sprintf("CSPScore=%d/100, Issues=%s, CSP=%q", score, strings.Join(issues, ","), csp),
		Fix:                        "Use strict script-src with nonce/hash, remove unsafe-inline/unsafe-eval, and define object-src 'none' and base-uri 'self'.",
		IsPotentiallyFalsePositive: true,
	})

	return findings, nil
}
