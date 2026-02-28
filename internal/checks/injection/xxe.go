package injection

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

// CheckXXE attempts to detect XML External Entity (XXE) vulnerabilities.
func CheckXXE(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	// XXE Payload: Defines an entity 'xxe' with a specific value and tries to reference it.
	// We use a safe string reflection check instead of trying to read /etc/passwd to avoid false negatives due to permissions.
	canary := "PRS_XXE_TEST"
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe "%s">
]>
<root>
  <name>&xxe;</name>
  <value>&xxe;</value>
</root>`, canary)

	// Target the URL with a POST request containing XML
	req, err := ctxpkg.NewRequest(ctx, "POST", ctx.FinalURL.String(), strings.NewReader(payload))
	if err != nil {
		return findings, err
	}

	// Set headers to encourage XML parsing
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml")

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := engine.DecodeResponseBody(resp)
	bodyString := string(bodyBytes)

	// Logic:
	// 1. If the server simply echoes the request, 'canary' appears ONCE
	// 2. If the server parses and expands the entity, 'canary' appears TWICE
	if strings.Count(bodyString, canary) >= 2 {
		msg := msges.GetMessage("XXE_DETECTED")
		findings = append(findings, report.Finding{
			ID:                         "XXE_DETECTED",
			Category:                   string(checks.CategoryInputHandling),
			Severity:                   report.SeverityHigh,
			Confidence:                 report.ConfidenceHigh,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, canary),
			Evidence:                   fmt.Sprintf("The canary string '%s' was reflected multiple times, indicating XML entity expansion.", canary),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	// Check Forms
	forms := extractForms(ctx)
	for _, form := range forms {
		if form.Method != "POST" {
			continue
		}

		var targetURL string
		if form.ActionURL == "" {
			targetURL = ctx.FinalURL.String()
		} else {
			u, err := url.Parse(form.ActionURL)
			if err == nil {
				targetURL = ctx.FinalURL.ResolveReference(u).String()
			} else {
				continue
			}
		}

		req, err := ctxpkg.NewRequest(ctx, "POST", targetURL, strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/xml")

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := engine.DecodeResponseBody(resp)
		resp.Body.Close()

		if strings.Contains(string(bodyBytes), canary) {
			msg := msges.GetMessage("XXE_DETECTED")
			findings = append(findings, report.Finding{
				ID:                         "XXE_DETECTED",
				Category:                   string(checks.CategoryInputHandling),
				Severity:                   report.SeverityHigh,
				Confidence:                 report.ConfidenceHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, canary),
				Evidence:                   "Entity expansion detected in response.",
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	return findings, nil
}
