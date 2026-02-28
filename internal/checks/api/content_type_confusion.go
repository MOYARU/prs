package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckContentTypeConfusion(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil
	}

	if strings.Contains(ctx.Response.Header.Get("Content-Type"), "application/json") {
		req, err := ctxpkg.NewRequest(ctx, "POST", ctx.FinalURL.String(), strings.NewReader(`{"test":"value"}`))
		if err != nil {
			return findings, err
		}
		req.Header.Set("Content-Type", "text/plain") // Send as text/plain
		req.Header.Set("Accept", "application/json") // Still prefer JSON in response

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			return findings, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			msg := msges.GetMessage("JSON_API_TEXT_PLAIN_ALLOWED")
			findings = append(findings, report.Finding{
				ID:                         "JSON_API_TEXT_PLAIN_ALLOWED",
				Category:                   string(checks.CategoryAPISecurity),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceMedium,
				Title:                      msg.Title,
				Message:                    msg.Message,
				Evidence:                   "Request with Content-Type: text/plain was processed as JSON.",
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	// Check 2: Accept header ignored
	req, err := ctxpkg.NewRequest(ctx, "GET", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("Accept", "text/html") // Request HTML content

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") && !strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		msg := msges.GetMessage("ACCEPT_HEADER_IGNORED")
		findings = append(findings, report.Finding{
			ID:                         "ACCEPT_HEADER_IGNORED",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "Server returned application/json despite Accept: text/html header.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	// Check 3: JSONP enabled
	findings = append(findings, checkJSONP(ctx)...)

	return findings, nil
}

// checkJSONP detects if an endpoint supports JSONP callbacks.
func checkJSONP(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	canary := "prs_jsonp_canary"
	paramNames := []string{"callback", "jsonp"}

	u, err := url.Parse(ctx.FinalURL.String())
	if err != nil {
		return findings
	}

	for _, paramName := range paramNames {
		// Create a copy of the query parameters
		q := u.Query()
		// Set the JSONP callback parameter
		q.Set(paramName, canary)
		u.RawQuery = q.Encode()

		req, err := ctxpkg.NewRequest(ctx, "GET", u.String(), nil)
		if err != nil {
			continue
		}

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, err := engine.DecodeResponseBody(resp)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyString := string(bodyBytes)

			// Check if the response is wrapped in the canary function
			if strings.HasPrefix(bodyString, canary+"(") && (strings.HasSuffix(bodyString, ")") || strings.HasSuffix(bodyString, ");")) {
				msg := msges.GetMessage("JSONP_ENABLED")
				findings = append(findings, report.Finding{
					ID:       "JSONP_ENABLED",
					Category: string(checks.CategoryAPISecurity),
					Severity: report.SeverityMedium,
					Title:    msg.Title,
					Message:  fmt.Sprintf(msg.Message, paramName),
					Evidence: fmt.Sprintf("Callback parameter '%s' triggered a JSONP response.", paramName),
					Fix:      msg.Fix,
				})
				return findings // Found it, no need to check other param names
			}
		}
	}
	return findings
}
