package injection

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

var (
	domScriptBlockRegex = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	domSourceRegex      = regexp.MustCompile(`(?i)(location\.(hash|search|href|pathname)|document\.(URL|documentURI|location|referrer)|window\.name|localStorage|sessionStorage|URLSearchParams\s*\(\s*location\.search\s*\)|decodeURIComponent\s*\(\s*location\.(hash|search)\s*\))`)
	domSinkRegex        = regexp.MustCompile(`(?i)\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|Function|setTimeout|setInterval|\.html\s*\(|\.append\s*\(|\.prepend\s*\(|\$\(\s*[^)]*\s*\)\.html\s*\()\b`)

	domFlowRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?is)\b(innerHTML|outerHTML|insertAdjacentHTML)\s*=\s*[^;\n]{0,260}(location\.(hash|search|href|pathname)|document\.(URL|documentURI|location|referrer)|window\.name|localStorage|sessionStorage)`),
		regexp.MustCompile(`(?is)\b(document\.write|document\.writeln|eval|Function|setTimeout|setInterval)\s*\(\s*[^)]{0,260}(location\.(hash|search|href|pathname)|document\.(URL|documentURI|location|referrer)|window\.name|localStorage|sessionStorage)`),
		regexp.MustCompile(`(?is)\$\(\s*(location\.(hash|search|href)|document\.(URL|location)|window\.name)\s*\)\s*\.\s*(html|append|prepend)\s*\(`),
	}
)

// CheckDOMXSSPassive performs passive DOM XSS signal detection from client-side script code.
func CheckDOMXSSPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Response == nil || ctx.FinalURL == nil || len(ctx.BodyBytes) == 0 {
		return findings, nil
	}

	contentType := strings.ToLower(ctx.Response.Header.Get("Content-Type"))
	isHTML := strings.Contains(contentType, "text/html")
	isJS := strings.Contains(contentType, "javascript") || strings.Contains(contentType, "application/ecmascript") || strings.Contains(contentType, "text/ecmascript")
	if !isHTML && !isJS {
		return findings, nil
	}

	body := string(ctx.BodyBytes)
	scriptUnits := make([]string, 0, 4)
	if isJS {
		scriptUnits = append(scriptUnits, body)
	} else {
		for _, m := range domScriptBlockRegex.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			unit := strings.TrimSpace(m[1])
			if unit == "" {
				continue
			}
			scriptUnits = append(scriptUnits, unit)
		}
	}
	if len(scriptUnits) == 0 {
		return findings, nil
	}

	flows := make([]string, 0, 4)
	foundSource := false
	foundSink := false
	for _, unit := range scriptUnits {
		if domSourceRegex.MatchString(unit) {
			foundSource = true
		}
		if domSinkRegex.MatchString(unit) {
			foundSink = true
		}
		for _, re := range domFlowRegexes {
			for _, match := range re.FindAllString(unit, 2) {
				flows = append(flows, compactDOMEvidence(match))
				if len(flows) >= 3 {
					break
				}
			}
			if len(flows) >= 3 {
				break
			}
		}
	}

	affected := []string{ctx.FinalURL.String()}
	if len(flows) > 0 {
		findings = append(findings, report.Finding{
			ID:                         "DOM_XSS_POSSIBLE",
			Category:                   string(checks.CategoryClientSecurity),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceMedium,
			Title:                      "Possible DOM XSS Flow Detected",
			Message:                    "Client-side code appears to route DOM-controlled input sources into executable/HTML sinks.",
			Evidence:                   strings.Join(flows, " | "),
			Fix:                        "Avoid unsafe sinks (innerHTML/eval/document.write). Sanitize and strictly validate DOM-driven inputs, and prefer safe APIs (textContent, createElement).",
			AffectedURLs:               affected,
			IsPotentiallyFalsePositive: true,
		})
		return findings, nil
	}

	if foundSource && foundSink {
		findings = append(findings, report.Finding{
			ID:                         "DOM_XSS_RISKY_SOURCE_SINK",
			Category:                   string(checks.CategoryClientSecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceLow,
			Title:                      "DOM XSS Risky Source/Sink Combination",
			Message:                    "DOM XSS-relevant sources and sinks are present in client-side code. Manual verification is recommended.",
			Evidence:                   fmt.Sprintf("URL=%s, sources=true, sinks=true", ctx.FinalURL.String()),
			Fix:                        "Review JavaScript data flow from location/document sources to dangerous sinks and enforce sanitization/encoding boundaries.",
			AffectedURLs:               affected,
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings, nil
}

func compactDOMEvidence(s string) string {
	compact := strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	if len(compact) > 200 {
		return compact[:200] + "..."
	}
	return compact
}
