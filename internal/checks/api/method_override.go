package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckMethodOverride(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil
	}

	normalPostReq, err := http.NewRequest("POST", ctx.FinalURL.String(), strings.NewReader(""))
	if err != nil {
		return findings, err
	}
	normalPostResp, err := ctx.HTTPClient.Do(normalPostReq)
	if err != nil {
		return findings, err
	}
	defer normalPostResp.Body.Close()

	overrideMethod := "DELETE"
	overridePostReq, err := http.NewRequest("POST", ctx.FinalURL.String(), strings.NewReader(""))
	if err != nil {
		return findings, err
	}
	overridePostReq.Header.Set("X-HTTP-Method-Override", overrideMethod)
	overridePostResp, err := ctx.HTTPClient.Do(overridePostReq)
	if err != nil {
		return findings, err
	}
	defer overridePostResp.Body.Close()

	if normalPostResp.StatusCode != overridePostResp.StatusCode &&
		(overridePostResp.StatusCode == http.StatusOK || overridePostResp.StatusCode == http.StatusNoContent || overridePostResp.StatusCode == http.StatusAccepted) {
		msg := msges.GetMessage("METHOD_OVERRIDE_ALLOWED")
		findings = append(findings, report.Finding{
			ID:                         "METHOD_OVERRIDE_ALLOWED",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, overrideMethod),
			Evidence:                   fmt.Sprintf("POST with X-HTTP-Method-Override: %s returned status %d, different from a normal POST (%d).", overrideMethod, overridePostResp.StatusCode, normalPostResp.StatusCode),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
