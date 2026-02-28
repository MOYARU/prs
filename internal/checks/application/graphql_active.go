package application

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

// CheckGraphQLAuthBoundaryActive probes GraphQL endpoints for weak unauthenticated access boundaries.
func CheckGraphQLAuthBoundaryActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.HTTPClient == nil || ctx.FinalURL == nil {
		return findings, nil
	}

	paths := []string{"/graphql", "/api/graphql", "/graph"}
	query := `{"query":"query { __typename }"}`
	for _, p := range paths {
		targetURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + p

		req1, err := newScanRequest(ctx, http.MethodPost, targetURL, strings.NewReader(query))
		if err != nil {
			continue
		}
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := ctx.HTTPClient.Do(req1)
		if err != nil {
			continue
		}
		body1, _ := engine.DecodeResponseBody(resp1)
		resp1.Body.Close()
		b1 := strings.ToLower(string(body1))

		req2, err := newScanRequest(ctx, http.MethodPost, targetURL, strings.NewReader(query))
		if err != nil {
			continue
		}
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("Authorization", "Bearer prs-invalid-token")
		resp2, err := ctx.HTTPClient.Do(req2)
		if err != nil {
			continue
		}
		body2, _ := engine.DecodeResponseBody(resp2)
		resp2.Body.Close()
		b2 := strings.ToLower(string(body2))

		noAuthDenied := strings.Contains(b1, "unauthorized") || strings.Contains(b1, "forbidden")
		invalidAuthDenied := strings.Contains(b2, "unauthorized") || strings.Contains(b2, "forbidden")
		looksData := strings.Contains(b1, `"data"`) && strings.Contains(b1, "__typename")

		if resp1.StatusCode == http.StatusOK &&
			resp2.StatusCode == http.StatusOK &&
			looksData &&
			!noAuthDenied &&
			!invalidAuthDenied {
			findings = append(findings, report.Finding{
				ID:                         "GRAPHQL_AUTH_BOUNDARY_WEAK",
				Category:                   string(checks.CategoryAPISecurity),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceLow,
				Validation:                 report.ValidationProbable,
				Title:                      "GraphQL Authentication Boundary Appears Weak",
				Message:                    "GraphQL endpoint returned data both without auth and with an invalid bearer token. Review resolver-level authorization controls.",
				Evidence:                   fmt.Sprintf("Path=%s, NoAuthStatus=%d, InvalidAuthStatus=%d", p, resp1.StatusCode, resp2.StatusCode),
				Fix:                        "Enforce authentication and resolver-level authorization checks for sensitive fields/mutations. Use explicit allow/deny policy.",
				IsPotentiallyFalsePositive: true,
			})
			break
		}
	}

	return findings, nil
}
