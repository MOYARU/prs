package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckRateLimitAbsence(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response == nil || ctx.Response.Request == nil {
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

	// If server already signals throttling, do not report missing headers.
	if ctx.Response.StatusCode == http.StatusTooManyRequests {
		return findings, nil
	}

	if ctx.Response.Header.Get("Retry-After") == "" {
		msg := msges.GetMessage("RETRY_AFTER_HEADER_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "RETRY_AFTER_HEADER_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "The 'Retry-After' header was not found in the response.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	// Check for X-RateLimit-* headers absence
	xRateLimitFound := false
	for header := range ctx.Response.Header {
		if strings.HasPrefix(strings.ToLower(header), "x-ratelimit-") {
			xRateLimitFound = true
			break
		}
	}

	if !xRateLimitFound {
		msg := msges.GetMessage("X_RATELIMIT_HEADERS_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "X_RATELIMIT_HEADERS_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "No 'X-RateLimit-*' headers were found in the response.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
