package http

import (
	"fmt"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

// CheckCachePoisoningPassive inspects cache-related header combinations for poisoning risk signals.
func CheckCachePoisoningPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Response == nil || ctx.FinalURL == nil {
		return findings, nil
	}

	h := ctx.Response.Header
	cc := strings.ToLower(h.Get("Cache-Control"))
	vary := strings.ToLower(h.Get("Vary"))
	setCookie := h.Get("Set-Cookie") != ""
	xcache := strings.TrimSpace(h.Get("X-Cache")) != "" || strings.TrimSpace(h.Get("CF-Cache-Status")) != ""

	// Signal A: public cacheability + Set-Cookie.
	if setCookie && (strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage")) {
		findings = append(findings, report.Finding{
			ID:                         "CACHE_PUBLIC_WITH_SET_COOKIE",
			Category:                   string(checks.CategoryHTTPProtocol),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceLow,
			Title:                      "Cache Poisoning Risk Signal: Public Cache with Set-Cookie",
			Message:                    "Response appears publicly cacheable while setting cookies. This can increase cache confusion and data-mix risks in shared cache layers.",
			Evidence:                   fmt.Sprintf("Cache-Control=%q, Set-Cookie=true, URL=%s", h.Get("Cache-Control"), ctx.FinalURL.String()),
			Fix:                        "Avoid public caching for personalized responses. Use Cache-Control: private/no-store and separate cache keys for user/session variants.",
			IsPotentiallyFalsePositive: true,
		})
	}

	// Signal B: cache is present, but Vary looks insufficient for proxy-sensitive headers.
	if xcache && vary != "" && !strings.Contains(vary, "accept-encoding") {
		findings = append(findings, report.Finding{
			ID:                         "CACHE_VARY_KEY_WEAK",
			Category:                   string(checks.CategoryHTTPProtocol),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceLow,
			Title:                      "Cache Key Weakness Signal (Passive)",
			Message:                    "Caching headers are present, but Vary appears narrow for robust cache-key separation.",
			Evidence:                   fmt.Sprintf("Vary=%q, X-Cache/CF-Cache-Status present, URL=%s", h.Get("Vary"), ctx.FinalURL.String()),
			Fix:                        "Define cache key strategy explicitly (host/proto/path/query and relevant headers). Keep Vary minimal but sufficient for representation separation.",
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings, nil
}

// CheckRequestSmugglingPassive identifies protocol ambiguity indicators without active probing.
func CheckRequestSmugglingPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Response == nil || ctx.FinalURL == nil {
		return findings, nil
	}
	h := ctx.Response.Header
	conn := strings.ToLower(h.Get("Connection"))
	te := strings.ToLower(h.Get("Transfer-Encoding"))
	trailer := strings.ToLower(h.Get("Trailer"))
	via := h.Get("Via")

	signals := make([]string, 0, 4)
	if strings.Contains(conn, "transfer-encoding") || strings.Contains(conn, "te") {
		signals = append(signals, "connection-hop-by-hop-te")
	}
	if te != "" && te != "chunked" {
		signals = append(signals, "non-standard-transfer-encoding")
	}
	if trailer != "" {
		signals = append(signals, "trailer-present")
	}
	if via != "" {
		signals = append(signals, "proxy-chain-via")
	}

	if len(signals) == 0 {
		return findings, nil
	}
	findings = append(findings, report.Finding{
		ID:                         "REQUEST_SMUGGLING_PASSIVE_INDICATOR",
		Category:                   string(checks.CategoryHTTPProtocol),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      "HTTP Request Smuggling Risk Signal (Passive)",
		Message:                    "Protocol-level ambiguity indicators were detected in response headers. Validate front-end/back-end parsing consistency.",
		Evidence:                   fmt.Sprintf("Signals=%s, Connection=%q, Transfer-Encoding=%q, URL=%s", strings.Join(signals, ","), h.Get("Connection"), h.Get("Transfer-Encoding"), ctx.FinalURL.String()),
		Fix:                        "Normalize hop-by-hop headers at edge proxies, enforce strict HTTP parsing, and align front/back-end request handling behavior.",
		IsPotentiallyFalsePositive: true,
	})
	return findings, nil
}
