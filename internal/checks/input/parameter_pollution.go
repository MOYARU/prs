package input

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

// CheckParameterPollution checks for Parameter Pollution vulnerabilities.
func CheckParameterPollution(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return checkParameterPollutionPassive(ctx), nil
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		return findings, nil
	}

	originalReq, err := ctxpkg.NewRequest(ctx, "GET", u.String(), nil)
	if err != nil {
		return findings, nil
	}
	originalResp, err := ctx.HTTPClient.Do(originalReq)
	if err != nil {
		return findings, nil
	}
	originalBodyBytes, _ := engine.DecodeResponseBody(originalResp)
	originalResp.Body.Close()
	originalBody := string(originalBodyBytes)
	originalStatus := originalResp.StatusCode

	for param, values := range queryParams {
		if len(values) == 0 {
			continue
		}

		newParams := url.Values{}
		for k, v := range queryParams {
			newParams[k] = v
		}
		newParams.Add(param, "polluted_value")

		u.RawQuery = newParams.Encode()
		req, err := ctxpkg.NewRequest(ctx, "GET", u.String(), nil)
		if err != nil {
			continue
		}

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := engine.DecodeResponseBody(resp)
		resp.Body.Close()
		bodyString := string(bodyBytes)
		if resp.StatusCode != originalStatus &&
			strings.Contains(bodyString, "polluted_value") &&
			!strings.Contains(originalBody, "polluted_value") {
			msg := msges.GetMessage("PARAMETER_POLLUTION_DETECTED")
			findings = append(findings, report.Finding{
				ID:                         "PARAMETER_POLLUTION_DETECTED",
				Category:                   string(checks.CategoryInputHandling),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, param),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	return findings, nil
}

func CheckParameterPollutionPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	return checkParameterPollutionPassive(ctx), nil
}

func checkParameterPollutionPassive(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx == nil || ctx.FinalURL == nil {
		return findings
	}

	rawQuery := ctx.FinalURL.RawQuery
	if rawQuery == "" {
		return findings
	}

	counts := make(map[string]int)
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		key := pair
		if i := strings.Index(pair, "="); i >= 0 {
			key = pair[:i]
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		counts[decodedKey]++
	}

	var duplicated []string
	for k, c := range counts {
		if c > 1 {
			duplicated = append(duplicated, fmt.Sprintf("%s(x%d)", k, c))
		}
	}
	if len(duplicated) == 0 {
		return findings
	}

	findings = append(findings, report.Finding{
		ID:                         "PARAMETER_POLLUTION_PASSIVE_INDICATOR",
		Category:                   string(checks.CategoryInputHandling),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      "Duplicate Query Parameters Found (Passive Indicator)",
		Message:                    fmt.Sprintf("Duplicate query parameter keys were found in the URL: %s", strings.Join(duplicated, ", ")),
		Evidence:                   "Raw query: " + rawQuery,
		Fix:                        "Normalize or reject duplicated query parameters at the edge and backend, and define deterministic parsing behavior.",
		IsPotentiallyFalsePositive: true,
	})

	return findings
}
