package api

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

// CheckRateLimitAbsencePassive performs passive header-based checks only.
func CheckRateLimitAbsencePassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Response == nil || ctx.Response.Request == nil {
		return findings, nil
	}

	path := ""
	if reqURL, err := url.Parse(ctx.Response.Request.URL.String()); err == nil {
		path = strings.ToLower(reqURL.Path)
	}
	contentType := strings.ToLower(ctx.Response.Header.Get("Content-Type"))
	isLikelyAPI := strings.Contains(contentType, "json") ||
		strings.HasPrefix(path, "/api") ||
		strings.Contains(path, "/graphql")
	if !isLikelyAPI {
		return findings, nil
	}
	if ctx.Response.StatusCode == http.StatusTooManyRequests {
		return findings, nil
	}

	if ctx.Response.Header.Get("Retry-After") == "" {
		msg := msges.GetMessage("RETRY_AFTER_HEADER_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "RETRY_AFTER_HEADER_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityInfo,
			Confidence:                 report.ConfidenceLow,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "Passive check: 'Retry-After' header was not found.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: true,
		})
	}

	if !hasXRateLimitHeaders(ctx.Response.Header) {
		msg := msges.GetMessage("X_RATELIMIT_HEADERS_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "X_RATELIMIT_HEADERS_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceLow,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "Passive check: no 'X-RateLimit-*' headers were found.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: true,
		})
	}
	return findings, nil
}

// CheckRateLimitEnforcementActive verifies practical throttling behavior.
func CheckRateLimitEnforcementActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil {
		return findings, nil
	}

	totalRequests := 10
	throttled := false
	retryAfterSeen := false
	xRateLimitSeen := false

	for i := 0; i < totalRequests; i++ {
		req, err := newScanRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
		if err != nil {
			continue
		}
		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			throttled = true
		}
		if resp.Header.Get("Retry-After") != "" {
			retryAfterSeen = true
		}
		if hasXRateLimitHeaders(resp.Header) {
			xRateLimitSeen = true
		}
		resp.Body.Close()
		time.Sleep(40 * time.Millisecond)
	}

	if throttled {
		return findings, nil
	}

	findings = append(findings, report.Finding{
		ID:                         "RATE_LIMIT_NOT_ENFORCED_ACTIVE",
		Category:                   string(checks.CategoryAPISecurity),
		Severity:                   report.SeverityMedium,
		Confidence:                 report.ConfidenceMedium,
		Title:                      "Rate Limiting Not Enforced (Active)",
		Message:                    "Burst requests did not trigger throttling responses (429).",
		Evidence:                   fmt.Sprintf("Sent=%d rapid requests, 429=false, Retry-After=%t, X-RateLimit headers=%t", totalRequests, retryAfterSeen, xRateLimitSeen),
		Fix:                        "Apply per-IP/user/token rate limiting with server-side enforcement and clear throttle responses.",
		IsPotentiallyFalsePositive: true,
	})

	return findings, nil
}

func hasXRateLimitHeaders(h http.Header) bool {
	for header := range h {
		if strings.HasPrefix(strings.ToLower(header), "x-ratelimit-") {
			return true
		}
	}
	return false
}

func newScanRequest(scanCtx *ctxpkg.Context, method, target string, body io.Reader) (*http.Request, error) {
	if scanCtx != nil && scanCtx.RequestContext != nil {
		return http.NewRequestWithContext(scanCtx.RequestContext, method, target, body)
	}
	return http.NewRequest(method, target, body)
}
