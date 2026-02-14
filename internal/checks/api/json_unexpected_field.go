package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckJSONUnexpectedField(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil
	}
	// Only proceed if the original response is JSON
	if !strings.Contains(ctx.Response.Header.Get("Content-Type"), "application/json") {
		return findings, nil
	}

	// Parse the original JSON body
	var originalJSON map[string]interface{}
	err := json.Unmarshal(ctx.BodyBytes, &originalJSON)
	if err != nil {
		originalJSON = make(map[string]interface{})
	}

	// Add an unexpected field
	originalJSON["prs_unexpected_field"] = "prs_test_value"

	modifiedJSON, err := json.Marshal(originalJSON)
	if err != nil {
		return findings, fmt.Errorf("failed to marshal modified JSON: %w", err)
	}

	req, err := http.NewRequest("POST", ctx.FinalURL.String(), bytes.NewReader(modifiedJSON))
	if err != nil {
		return findings, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ctx.HTTPClient.Do(req) // Use the shared client from the context
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	// If the server still accepts the request with unexpected fields, flag it.
	if resp.StatusCode == http.StatusOK {
		msg := msges.GetMessage("JSON_UNEXPECTED_FIELD_INSERTION")
		findings = append(findings, report.Finding{
			ID:                         "JSON_UNEXPECTED_FIELD_INSERTION",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "Server responded with 200 OK to a POST request containing an unexpected JSON field ('prs_unexpected_field').",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
