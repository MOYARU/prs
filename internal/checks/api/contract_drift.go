package api

import (
	"fmt"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

// CheckAPIContractDriftPassive inspects API-like endpoints for representation/contract drift signals.
func CheckAPIContractDriftPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.FinalURL == nil || ctx.Response == nil {
		return findings, nil
	}

	path := strings.ToLower(ctx.FinalURL.Path)
	if !isLikelyAPIPath(path) {
		return findings, nil
	}

	contentType := strings.ToLower(ctx.Response.Header.Get("Content-Type"))
	body := strings.TrimSpace(string(ctx.BodyBytes))
	status := ctx.Response.StatusCode

	signals := make([]string, 0, 3)
	if strings.Contains(contentType, "text/html") {
		signals = append(signals, "api-path-returned-html")
	}
	if status >= 400 && strings.Contains(contentType, "application/json") && strings.Contains(strings.ToLower(body), "<html") {
		signals = append(signals, "json-content-type-with-html-body")
	}
	if status == 200 && strings.Contains(strings.ToLower(body), "\"error\"") {
		signals = append(signals, "200-status-error-field")
	}
	if len(signals) == 0 {
		return findings, nil
	}

	findings = append(findings, report.Finding{
		ID:                         "API_CONTRACT_DRIFT_PASSIVE",
		Category:                   string(checks.CategoryAPISecurity),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      "API Contract Drift Signal (Passive)",
		Message:                    "API-like endpoint shows response contract inconsistency that can increase security and reliability risk.",
		Evidence:                   fmt.Sprintf("Signals=%s, Status=%d, Content-Type=%q, URL=%s", strings.Join(signals, ","), status, ctx.Response.Header.Get("Content-Type"), ctx.FinalURL.String()),
		Fix:                        "Standardize API response envelopes, status-code semantics, and content types across success/error paths.",
		IsPotentiallyFalsePositive: true,
	})
	return findings, nil
}

func isLikelyAPIPath(path string) bool {
	return strings.Contains(path, "/api") ||
		strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") ||
		strings.HasSuffix(path, ".json") ||
		strings.Contains(path, "/graphql")
}
