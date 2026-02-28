package info

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/MOYARU/prs/internal/checks"
	"github.com/MOYARU/prs/internal/checks/application"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/config"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

type leakagePattern struct {
	MsgID string
	Match func(body string) bool
}

var oraErrorRegex = regexp.MustCompile(`ORA-\d{5}`)

var leakagePatterns = []leakagePattern{
	{
		MsgID: "INFORMATION_LEAKAGE_STACK_TRACE",
		Match: func(b string) bool {
			return false
		},
	},
	{
		MsgID: "INFORMATION_LEAKAGE_DB_ERROR",
		Match: func(b string) bool {
			return strings.Contains(b, "SQLSTATE") || oraErrorRegex.MatchString(b) || strings.Contains(b, "SQL error") ||
				strings.Contains(b, "JDBC error") || strings.Contains(b, "PostgreSQL error") || strings.Contains(b, "MySQL error") || strings.Contains(b, "db error")
		},
	},
}

func CheckInformationLeakage(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	policy := config.LoadScanPolicyFromPRS()

	bodyString := string(ctx.BodyBytes)

	for _, p := range leakagePatterns {
		matched := p.Match(bodyString)
		if p.MsgID == "INFORMATION_LEAKAGE_STACK_TRACE" {
			matched = isLikelyStackTrace(bodyString, policy.InfoLeakMinStackSignals)
		}
		if matched {
			msg := msges.GetMessage(p.MsgID) // Retrieve message
			evidence := ""
			if p.MsgID == "INFORMATION_LEAKAGE_STACK_TRACE" {
				evidence = extractStackTraceEvidence(bodyString)
			}
			findings = append(findings, report.Finding{
				ID:         p.MsgID,
				Category:   string(checks.CategoryInformationLeakage),
				Severity:   report.SeverityMedium,
				Confidence: report.ConfidenceHigh,
				Title:      msg.Title,
				Message:    msg.Message,
				Evidence:   evidence,
				Fix:        msg.Fix,
			})
		}
	}

	for headerName, headerValue := range ctx.Response.Header {
		lowerHeaderName := strings.ToLower(headerName)
		lowerHeaderValue := strings.ToLower(strings.Join(headerValue, " ")) // Join multiple values

		if lowerHeaderName == "x-powered-by" && lowerHeaderValue != "" {
			msg := msges.GetMessage("INFORMATION_LEAKAGE_X_POWERED_BY")
			findings = append(findings, report.Finding{
				ID:         "INFORMATION_LEAKAGE_X_POWERED_BY",
				Category:   string(checks.CategoryInformationLeakage),
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceMedium,
				Title:      msg.Title,
				Message:    fmt.Sprintf(msg.Message, lowerHeaderValue),
				Fix:        msg.Fix,
			})
		}
		if lowerHeaderName == "server" {
			if !(strings.Contains(lowerHeaderValue, "cloudflare") || strings.Contains(lowerHeaderValue, "aws") || strings.Contains(lowerHeaderValue, "gcp") || strings.Contains(lowerHeaderValue, "akamai")) {
				if strings.Contains(lowerHeaderValue, "nginx") || strings.Contains(lowerHeaderValue, "apache") || strings.Contains(lowerHeaderValue, "iis") {
					msg := msges.GetMessage("INFORMATION_LEAKAGE_SERVER_HEADER")
					findings = append(findings, report.Finding{
						ID:         "INFORMATION_LEAKAGE_SERVER_HEADER",
						Category:   string(checks.CategoryInformationLeakage),
						Severity:   report.SeverityLow,
						Confidence: report.ConfidenceMedium,
						Title:      msg.Title,
						Message:    fmt.Sprintf(msg.Message, lowerHeaderValue),
						Fix:        msg.Fix,
					})
				}
			}
		}
	}

	// Framework Signature
	if strings.Contains(bodyString, "X-AspNet-Version") ||
		strings.Contains(bodyString, "X-Generator") ||
		strings.Contains(bodyString, "WordPress") ||
		strings.Contains(bodyString, "Joomla!") {
		msg := msges.GetMessage("INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE")
		findings = append(findings, report.Finding{
			ID:         "INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE",
			Category:   string(checks.CategoryInformationLeakage),
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceMedium,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	// Debug/Meta Endpoints
	if ctx.Mode == ctxpkg.Active {
		// Common debug/meta endpoints to probe
		debugEndpoints := []string{
			"/.env", "/.git/config", "/.git/HEAD", "/debug", "/admin", "/phpinfo.php",
			"/server-status", "/~root", "/~admin", "/manager/html", "/jmx-console",
			"/config.json", "/api-docs", "/v2/api-docs", "/swagger.json", "/actuator/env",
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, 10)

		for _, endpoint := range debugEndpoints {
			wg.Add(1)
			go func(endpoint string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				endpointURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + endpoint
				req, err := ctxpkg.NewRequest(ctx, "GET", endpointURL, nil)
				if err != nil {
					return
				}

				resp, err := ctx.HTTPClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					bodyBytes, _ := engine.DecodeResponseBody(resp)
					bodyString := string(bodyBytes)

					if len(bodyString) >= policy.InfoLeakMinBodyLen && !application.IsErrorPage(bodyString, resp.StatusCode) {
						msg := msges.GetMessage("INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT")
						mu.Lock()
						findings = append(findings, report.Finding{
							ID:         "INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT",
							Category:   string(checks.CategoryInformationLeakage),
							Severity:   report.SeverityMedium,
							Confidence: report.ConfidenceMedium,
							Title:      msg.Title,
							Message:    fmt.Sprintf(msg.Message, endpoint),
							Fix:        msg.Fix,
						})
						mu.Unlock()
					}
				}
			}(endpoint)
		}
		wg.Wait()
	}

	return findings, nil
}

func extractStackTraceEvidence(body string) string {
	lines := strings.Split(body, "\n")
	candidates := []string{
		"stack trace",
		"traceback",
		"panic:",
		"exception",
		" at ",
		".java:",
		".go:",
		".cs:",
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, c := range candidates {
			if strings.Contains(lower, c) {
				if len(trimmed) > 240 {
					return trimmed[:240] + "..."
				}
				return trimmed
			}
		}
	}

	if len(body) > 240 {
		return strings.TrimSpace(body[:240]) + "..."
	}
	return strings.TrimSpace(body)
}

func isLikelyStackTrace(body string, minSignals int) bool {
	evidence := extractStackTraceEvidence(body)
	if evidence == "" {
		return false
	}
	if minSignals <= 0 {
		minSignals = 2
	}
	lowerBody := strings.ToLower(body)
	strongSignals := 0
	if strings.Contains(lowerBody, "stack trace") || strings.Contains(lowerBody, "traceback") || strings.Contains(lowerBody, "panic:") {
		strongSignals++
	}
	if strings.Contains(lowerBody, ".java:") || strings.Contains(lowerBody, ".go:") || strings.Contains(lowerBody, ".cs:") {
		strongSignals++
	}
	if strings.Contains(lowerBody, "exception") {
		strongSignals++
	}
	if strings.Contains(lowerBody, "\n\tat ") || strings.Contains(lowerBody, "\nat ") {
		strongSignals++
	}
	return strongSignals >= minSignals
}
