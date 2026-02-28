package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

func checkHostHeaderInjection(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil {
		return findings
	}

	canary := "prs-host-header.example"
	req, err := ctxpkg.NewRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}
	req.Host = canary
	req.Header.Set("X-Forwarded-Host", canary)
	req.Header.Set("X-Host", canary)

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	bodyBytes, _ := engine.DecodeResponseBody(resp)
	body := strings.ToLower(string(bodyBytes))
	loc := strings.ToLower(resp.Header.Get("Location"))
	resp.Body.Close()

	baseline := strings.ToLower(string(ctx.BodyBytes))
	if (strings.Contains(body, canary) && !strings.Contains(baseline, canary)) ||
		(strings.Contains(loc, canary) && !strings.Contains(strings.ToLower(ctx.Response.Header.Get("Location")), canary)) {
		findings = append(findings, report.Finding{
			ID:                         "HOST_HEADER_INJECTION_POSSIBLE",
			Category:                   string(checks.CategoryHTTPProtocol),
			Severity:                   report.SeverityHigh,
			Confidence:                 report.ConfidenceMedium,
			Validation:                 report.ValidationProbable,
			Title:                      "Host Header Injection Possible",
			Message:                    "Injected Host/X-Forwarded-Host values were reflected in response body or redirect location.",
			Evidence:                   fmt.Sprintf("Canary host=%s reflected in body/location", canary),
			Fix:                        "Do not trust user-supplied host headers. Enforce canonical host validation at edge and app layers.",
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings
}

func checkCachePoisoningActive(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil || ctx.Response == nil {
		return findings
	}

	cacheSignal := ctx.Response.Header.Get("X-Cache") != "" ||
		ctx.Response.Header.Get("CF-Cache-Status") != "" ||
		strings.Contains(strings.ToLower(ctx.Response.Header.Get("Cache-Control")), "public")
	if !cacheSignal {
		return findings
	}

	canary := "prs-cache-poison.example"
	poisonReq, err := ctxpkg.NewRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}
	poisonReq.Header.Set("X-Forwarded-Host", canary)
	poisonReq.Header.Set("X-Original-Host", canary)

	poisonResp, err := ctx.HTTPClient.Do(poisonReq)
	if err != nil {
		return findings
	}
	poisonBodyBytes, _ := io.ReadAll(io.LimitReader(poisonResp.Body, 512*1024))
	poisonResp.Body.Close()
	poisonBody := strings.ToLower(string(poisonBodyBytes))
	if !strings.Contains(poisonBody, canary) && !strings.Contains(strings.ToLower(poisonResp.Header.Get("Location")), canary) {
		return findings
	}

	followReq, err := ctxpkg.NewRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}
	followResp, err := ctx.HTTPClient.Do(followReq)
	if err != nil {
		return findings
	}
	followBodyBytes, _ := io.ReadAll(io.LimitReader(followResp.Body, 512*1024))
	followResp.Body.Close()
	followBody := strings.ToLower(string(followBodyBytes))

	if strings.Contains(followBody, canary) || strings.Contains(strings.ToLower(followResp.Header.Get("Location")), canary) {
		findings = append(findings, report.Finding{
			ID:                         "CACHE_POISONING_ACTIVE_SIGNAL",
			Category:                   string(checks.CategoryHTTPProtocol),
			Severity:                   report.SeverityHigh,
			Confidence:                 report.ConfidenceMedium,
			Validation:                 report.ValidationProbable,
			Title:                      "Cache Poisoning Active Signal",
			Message:                    "Injected host metadata appears persisted across subsequent requests, indicating possible shared-cache key poisoning risk.",
			Evidence:                   fmt.Sprintf("Canary=%s appeared in follow-up response after poison attempt", canary),
			Fix:                        "Normalize untrusted forwarding headers, harden cache key composition, and segregate cache by trusted host context.",
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings
}
