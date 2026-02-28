package network

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckCORSConfiguration(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx == nil || ctx.Response == nil || ctx.FinalURL == nil {
		return findings, nil
	}

	if ctx.Response.Header.Get("Access-Control-Allow-Origin") == "*" {
		msg := msges.GetMessage("CORS_WILDCARD_ORIGIN")
		findings = append(findings, report.Finding{
			ID:         "CORS_WILDCARD_ORIGIN",
			Category:   string(checks.CategoryNetwork),
			Severity:   report.SeverityMedium,
			Confidence: report.ConfidenceHigh,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}
	if ctx.Response.Header.Get("Access-Control-Allow-Origin") == "*" &&
		strings.EqualFold(ctx.Response.Header.Get("Access-Control-Allow-Credentials"), "true") {
		findings = append(findings, report.Finding{
			ID:                         "CORS_WILDCARD_WITH_CREDENTIALS",
			Category:                   string(checks.CategoryNetwork),
			Severity:                   report.SeverityHigh,
			Confidence:                 report.ConfidenceHigh,
			Validation:                 report.ValidationConfirmed,
			Title:                      "CORS Wildcard with Credentials Enabled",
			Message:                    "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true. This is an unsafe CORS policy combination.",
			Evidence:                   fmt.Sprintf("ACAO=%q, ACAC=%q", ctx.Response.Header.Get("Access-Control-Allow-Origin"), ctx.Response.Header.Get("Access-Control-Allow-Credentials")),
			Fix:                        "Do not use wildcard origins with credentials. Return a strict allowlisted origin and set Vary: Origin.",
			IsPotentiallyFalsePositive: false,
		})
	}

	if ctx.Mode == ctxpkg.Active {
		testOrigins := []string{"https://malicious.com", "null"}
		acceptedOrigins := make(map[string]bool)

		for _, testOrigin := range testOrigins {
			req, err := ctxpkg.NewRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", testOrigin)
			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
			acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
			vary := strings.ToLower(resp.Header.Get("Vary"))
			resp.Body.Close()

			if acao == testOrigin {
				acceptedOrigins[testOrigin] = true
				msg := msges.GetMessage("CORS_ORIGIN_REFLECTION")
				findings = append(findings, report.Finding{
					ID:                         "CORS_ORIGIN_REFLECTION",
					Category:                   string(checks.CategoryNetwork),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceHigh,
					Validation:                 report.ValidationProbable,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, testOrigin),
					Evidence:                   fmt.Sprintf("Origin=%q reflected to ACAO, ACAC=%q, Vary=%q", testOrigin, acac, vary),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: false,
				})
			}
			if testOrigin == "null" && acao == "null" {
				findings = append(findings, report.Finding{
					ID:                         "CORS_NULL_ORIGIN_ALLOWED",
					Category:                   string(checks.CategoryNetwork),
					Severity:                   report.SeverityMedium,
					Confidence:                 report.ConfidenceMedium,
					Validation:                 report.ValidationProbable,
					Title:                      "CORS Null Origin Allowed",
					Message:                    "Server allows Origin: null, which can be abused by sandboxed/null-origin contexts.",
					Evidence:                   fmt.Sprintf("Origin=%q, ACAO=%q, ACAC=%q", testOrigin, acao, acac),
					Fix:                        "Disallow null origin unless explicitly required and strongly controlled.",
					IsPotentiallyFalsePositive: true,
				})
			}
		}

		if len(acceptedOrigins) == 2 {
			findings = append(findings, report.Finding{
				ID:                         "CORS_MULTI_ORIGIN_REFLECTION",
				Category:                   string(checks.CategoryNetwork),
				Severity:                   report.SeverityHigh,
				Confidence:                 report.ConfidenceHigh,
				Validation:                 report.ValidationConfirmed,
				Title:                      "CORS Dynamic Origin Reflection Confirmed",
				Message:                    "Multiple attacker-controlled origins were reflected by ACAO, confirming dynamic origin reflection behavior.",
				Evidence:                   "Reflected Origins: https://malicious.com, null",
				Fix:                        "Use an explicit allowlist for trusted origins and return only allowlisted origins.",
				IsPotentiallyFalsePositive: false,
			})
		}
	}

	return findings, nil
}
