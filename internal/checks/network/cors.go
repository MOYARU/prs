package network

import (
	"fmt"
	"net/http"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
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

	if ctx.Mode == ctxpkg.Active {
		testOrigin := "https://malicious.com"
		req, err := http.NewRequest("GET", ctx.FinalURL.String(), nil)
		if err != nil {
			return findings, err
		}
		req.Header.Set("Origin", testOrigin)

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			return findings, err
		}
		defer resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		if acao == testOrigin {
			msg := msges.GetMessage("CORS_ORIGIN_REFLECTION")
			findings = append(findings, report.Finding{
				ID:         "CORS_ORIGIN_REFLECTION",
				Category:   string(checks.CategoryNetwork),
				Severity:   report.SeverityHigh,
				Confidence: report.ConfidenceHigh,
				Title:      msg.Title,
				Message:    fmt.Sprintf(msg.Message, testOrigin),
				Fix:        msg.Fix,
			})
		}
	}

	return findings, nil
}
