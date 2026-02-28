package api

import (
	"fmt"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckMethodOverride(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return checkMethodOverridePassive(ctx), nil
	}

	normalPostReq, err := ctxpkg.NewRequest(ctx, "POST", ctx.FinalURL.String(), strings.NewReader(""))
	if err != nil {
		return findings, err
	}
	normalPostResp, err := ctx.HTTPClient.Do(normalPostReq)
	if err != nil {
		return findings, err
	}
	defer normalPostResp.Body.Close()

	overrideMethod := "DELETE"
	overridePostReq, err := ctxpkg.NewRequest(ctx, "POST", ctx.FinalURL.String(), strings.NewReader(""))
	if err != nil {
		return findings, err
	}
	overridePostReq.Header.Set("X-HTTP-Method-Override", overrideMethod)
	overridePostResp, err := ctx.HTTPClient.Do(overridePostReq)
	if err != nil {
		return findings, err
	}
	defer overridePostResp.Body.Close()

	normalSuccess := normalPostResp.StatusCode >= 200 && normalPostResp.StatusCode < 300
	overrideSuccess := overridePostResp.StatusCode >= 200 && overridePostResp.StatusCode < 300
	if !normalSuccess && overrideSuccess && normalPostResp.StatusCode != overridePostResp.StatusCode {
		msg := msges.GetMessage("METHOD_OVERRIDE_ALLOWED")
		findings = append(findings, report.Finding{
			ID:                         "METHOD_OVERRIDE_ALLOWED",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceLow,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, overrideMethod),
			Evidence:                   fmt.Sprintf("Normal POST failed with %d, but POST + X-HTTP-Method-Override:%s succeeded with %d.", normalPostResp.StatusCode, overrideMethod, overridePostResp.StatusCode),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings, nil
}

func CheckMethodOverridePassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	return checkMethodOverridePassive(ctx), nil
}

func checkMethodOverridePassive(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx == nil || ctx.Response == nil {
		return findings
	}

	allow := strings.ToUpper(ctx.Response.Header.Get("Allow"))
	acah := strings.ToUpper(ctx.Response.Header.Get("Access-Control-Allow-Headers"))
	if allow == "" && acah == "" {
		return findings
	}

	// Non-intrusive signal only: server advertises method override-related headers.
	if strings.Contains(acah, "X-HTTP-METHOD-OVERRIDE") ||
		strings.Contains(acah, "X-METHOD-OVERRIDE") ||
		strings.Contains(acah, "X-HTTP-METHOD") {
		findings = append(findings, report.Finding{
			ID:                         "METHOD_OVERRIDE_PASSIVE_INDICATOR",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityInfo,
			Confidence:                 report.ConfidenceLow,
			Title:                      "Method Override Header Accepted (Passive Indicator)",
			Message:                    "Response headers suggest HTTP method override headers may be accepted by the server.",
			Evidence:                   fmt.Sprintf("Access-Control-Allow-Headers=%q, Allow=%q", ctx.Response.Header.Get("Access-Control-Allow-Headers"), ctx.Response.Header.Get("Allow")),
			Fix:                        "If method override is unnecessary, block override headers (X-HTTP-Method-Override/X-Method-Override) at the gateway and backend.",
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings
}
