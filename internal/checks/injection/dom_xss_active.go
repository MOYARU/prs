package injection

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

// CheckDOMXSSActiveHeuristic performs low-impact active probing for DOM-XSS-prone flows.
// It does not execute JavaScript in a real browser; it strengthens passive signals with parameterized response checks.
func CheckDOMXSSActiveHeuristic(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil {
		return findings, nil
	}

	baseURL := ctx.FinalURL.String()
	u, err := url.Parse(baseURL)
	if err != nil {
		return findings, nil
	}
	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	baseline := string(ctx.BodyBytes)
	payload := `"><svg onload=alert('PRS_DOM_XSS_ACTIVE')>`
	probed := 0
	for _, param := range prioritizedParamKeys(query) {
		if probed >= 6 {
			break
		}
		values := query[param]
		if len(values) == 0 {
			continue
		}
		probed++

		newParams := cloneParams(query)
		newParams.Set(param, payload)
		u.RawQuery = newParams.Encode()

		req, err := ctxpkg.NewRequest(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}
		resp, err := doRequest(ctx.HTTPClient, req)
		if err != nil {
			continue
		}
		bodyBytes, _ := engine.DecodeResponseBody(resp)
		_ = resp.Body.Close()
		body := string(bodyBytes)
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(contentType, "text/html") {
			continue
		}

		flow, flowEvidence := hasParamDOMFlow(body, param)
		if !flow {
			continue
		}

		payloadReflected := strings.Contains(body, payload)
		sim := domSimilarityScore(strings.ToLower(body), strings.ToLower(baseline))
		if payloadReflected && sim < 0.98 {
			findings = append(findings, report.Finding{
				ID:                         "DOM_XSS_ACTIVE_PROBABLE",
				Category:                   string(checks.CategoryClientSecurity),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceMedium,
				Validation:                 report.ValidationProbable,
				Title:                      "DOM XSS Active Signal (Probable)",
				Message:                    "A parameterized request produced a DOM source-to-sink flow with reflected payload content.",
				Evidence:                   fmt.Sprintf("param=%s; %s; reflected_payload=true; similarity=%.2f", param, flowEvidence, sim),
				Fix:                        "Replace unsafe sinks (innerHTML/eval/document.write) with safe APIs and sanitize DOM-controlled input before rendering.",
				AffectedURLs:               []string{ctx.FinalURL.String(), u.String()},
				IsPotentiallyFalsePositive: true,
			})
			continue
		}

		findings = append(findings, report.Finding{
			ID:                         "DOM_XSS_ACTIVE_SIGNAL",
			Category:                   string(checks.CategoryClientSecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceLow,
			Title:                      "DOM XSS Active Signal",
			Message:                    "DOM source-to-sink flow related to a query parameter was observed in script code.",
			Evidence:                   fmt.Sprintf("param=%s; %s; reflected_payload=%v", param, flowEvidence, payloadReflected),
			Fix:                        "Perform browser-based verification and remove unsafe DOM sinks or sanitize untrusted sources.",
			AffectedURLs:               []string{ctx.FinalURL.String(), u.String()},
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings, nil
}

func domSimilarityScore(a, b string) float64 {
	a = strings.Join(strings.Fields(a), " ")
	b = strings.Join(strings.Fields(b), " ")
	if a == b {
		return 1.0
	}
	if a == "" || b == "" {
		return 0
	}
	tokensA := strings.Fields(a)
	tokensB := strings.Fields(b)
	setA := make(map[string]struct{}, len(tokensA))
	setB := make(map[string]struct{}, len(tokensB))
	for _, t := range tokensA {
		setA[t] = struct{}{}
	}
	for _, t := range tokensB {
		setB[t] = struct{}{}
	}
	inter := 0
	for t := range setA {
		if _, ok := setB[t]; ok {
			inter++
		}
	}
	union := len(setA) + len(setB) - inter
	if union <= 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func hasParamDOMFlow(body string, param string) (bool, string) {
	param = strings.TrimSpace(param)
	if param == "" {
		return false, ""
	}
	paramLower := strings.ToLower(param)
	pat1 := `urlsearchparams(location.search).get("` + paramLower + `")`
	pat2 := `urlsearchparams(location.search).get('` + paramLower + `')`
	pat3 := `new url(location.href).searchparams.get("` + paramLower + `")`
	pat4 := `new url(location.href).searchparams.get('` + paramLower + `')`
	pat5 := `searchparams.get("` + paramLower + `")`
	pat6 := `searchparams.get('` + paramLower + `')`
	scripts := domScriptBlockRegex.FindAllStringSubmatch(body, -1)
	for _, m := range scripts {
		if len(m) < 2 {
			continue
		}
		code := m[1]
		codeNorm := strings.ToLower(strings.Join(strings.Fields(code), ""))
		if !domSinkRegex.MatchString(code) {
			continue
		}
		if strings.Contains(codeNorm, pat1) ||
			strings.Contains(codeNorm, pat2) ||
			strings.Contains(codeNorm, pat3) ||
			strings.Contains(codeNorm, pat4) ||
			strings.Contains(codeNorm, pat5) ||
			strings.Contains(codeNorm, pat6) {
			return true, compactDOMEvidence(code)
		}
		if strings.Contains(codeNorm, "location.hash") {
			return true, compactDOMEvidence(code)
		}
	}
	return false, ""
}
