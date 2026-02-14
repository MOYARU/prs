package input

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

// CheckParameterPollution checks for Parameter Pollution vulnerabilities.
func CheckParameterPollution(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		return findings, nil
	}

	originalReq, err := http.NewRequest("GET", u.String(), nil)
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
		req, err := http.NewRequest("GET", u.String(), nil)
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
