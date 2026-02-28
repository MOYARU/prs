package authsession

import (
	"fmt"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

// CheckAuthSurfacePassive profiles authentication surface without sending attack payloads.
func CheckAuthSurfacePassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.FinalURL == nil || ctx.Response == nil {
		return findings, nil
	}

	path := strings.ToLower(ctx.FinalURL.Path)
	body := strings.ToLower(string(ctx.BodyBytes))
	signalSet := make([]string, 0, 8)

	if hasAny(path, "/login", "/signin", "/sign-in", "/auth", "/session", "/account") {
		signalSet = append(signalSet, "auth-like-path")
	}
	if hasAny(body, "type=\"password\"", "name=\"password\"", "otp", "one-time", "mfa", "2fa", "forgot password", "reset password") {
		signalSet = append(signalSet, "auth-form-keywords")
	}
	if len(ctx.Response.Cookies()) > 0 {
		signalSet = append(signalSet, "set-cookie-present")
	}
	if hasAny(strings.ToLower(ctx.Response.Header.Get("WWW-Authenticate")), "basic", "bearer", "digest") {
		signalSet = append(signalSet, "www-authenticate-present")
	}

	if len(signalSet) == 0 {
		return findings, nil
	}

	sev := report.SeverityInfo
	conf := report.ConfidenceLow
	if len(signalSet) >= 3 {
		sev = report.SeverityLow
		conf = report.ConfidenceMedium
	}

	findings = append(findings, report.Finding{
		ID:                         "AUTH_SURFACE_PROFILE",
		Category:                   string(checks.CategoryAuthSession),
		Severity:                   sev,
		Confidence:                 conf,
		Title:                      "Authentication Surface Profile (Passive)",
		Message:                    "Authentication-related attack surface indicators were identified. This is a profiling signal for hardening priority, not an exploit finding.",
		Evidence:                   fmt.Sprintf("Signals=%s, URL=%s", strings.Join(signalSet, ","), ctx.FinalURL.String()),
		Fix:                        "Review authentication endpoints for MFA enforcement, brute-force protections, secure cookie/session settings, and strict account recovery controls.",
		IsPotentiallyFalsePositive: true,
	})
	return findings, nil
}

func hasAny(s string, keys ...string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}
