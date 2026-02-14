package ssrf

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/crawler"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var ssrfPayloads = []string{
	"http://localhost",
	"http://127.0.0.1",
	"http://[::1]",
	"http://0.0.0.0",
	"%68%74%74%70%3A%2F%2F127.0.0.1", // URL Encoded http://127.0.0.1
}

var internalTargets = []struct {
	Port      int
	Signature string
	Service   string
}{
	{22, "SSH-2.0", "SSH"},
	{80, "HTTP/1.1", "Web"},
	{3306, "mysql", "MySQL"},
	{5432, "postgres", "PostgreSQL"},
	{6379, "redis", "Redis"},
	{8080, "Apache Tomcat", "Tomcat"},
}

func isExampleDomainResponse(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "<h1>example domain</h1>") &&
		(strings.Contains(l, "iana.org/domains/example") || strings.Contains(l, "this domain is for use in documentation"))
}

func CheckSSRF(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	callbackURL := "http://example.com"

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()
	baselineBody := string(ctx.BodyBytes)

	// 1. GET Parameters
	if len(queryParams) > 0 {
		for param, values := range queryParams {
			originalValue := ""
			if len(values) > 0 {
				originalValue = values[0]
			}
			if !isSSRFParamCandidate(param, originalValue) {
				continue
			}

			// Check External SSRF
			newParams := url.Values{}
			for k, v := range queryParams {
				newParams[k] = v
			}
			newParams.Set(param, callbackURL)
			u.RawQuery = newParams.Encode()
			requestURL := u.String()

			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				continue
			}

			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}

			bodyBytes, _ := engine.DecodeResponseBody(resp)
			bodyString := string(bodyBytes)
			resp.Body.Close()

			if ok, evidence := detectExternalFetchSignal(bodyString, baselineBody, callbackURL); ok {
				msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
				findings = append(findings, report.Finding{
					ID:                         "SSRF_CALLBACK_DETECTED",
					Category:                   string(checks.CategorySSRF),
					Severity:                   report.SeverityInfo,
					Confidence:                 report.ConfidenceLow,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, param),
					Evidence:                   fmt.Sprintf("%s; request=%s; status=%d", evidence, requestURL, resp.StatusCode),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
			}

			// Check Internal Port Scan
			for _, target := range internalTargets {
				localURL := fmt.Sprintf("http://127.0.0.1:%d", target.Port)
				newParamsLocal := url.Values{}
				for k, v := range queryParams {
					newParamsLocal[k] = v
				}
				newParamsLocal.Set(param, localURL)
				u.RawQuery = newParamsLocal.Encode()
				localRequestURL := u.String()

				reqLocal, err := http.NewRequest("GET", localRequestURL, nil)
				if err != nil {
					continue
				}

				respLocal, err := ctx.HTTPClient.Do(reqLocal)
				if err != nil {
					continue
				}
				bodyBytesLocal, _ := engine.DecodeResponseBody(respLocal)
				bodyStringLocal := string(bodyBytesLocal)
				respLocal.Body.Close()

				if strings.Contains(strings.ToLower(bodyStringLocal), strings.ToLower(target.Signature)) &&
					!strings.Contains(strings.ToLower(baselineBody), strings.ToLower(target.Signature)) {
					msg := msges.GetMessage("SSRF_LOCAL_ACCESS_DETECTED")
					findings = append(findings, report.Finding{
						ID:                         "SSRF_LOCAL_ACCESS_DETECTED",
						Category:                   string(checks.CategorySSRF),
						Severity:                   report.SeverityMedium,
						Confidence:                 report.ConfidenceMedium,
						Title:                      msg.Title,
						Message:                    fmt.Sprintf(msg.Message, param, target.Port, target.Service),
						Evidence:                   fmt.Sprintf("Response contained signature '%s' for port %d; request=%s; status=%d", target.Signature, target.Port, localRequestURL, respLocal.StatusCode),
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
					})
				}
			}
		}
	}

	// 2. POST Forms
	if strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		doc, err := html.Parse(bytes.NewReader(ctx.BodyBytes))
		if err == nil {
			forms := crawler.ExtractForms(doc)
			for _, form := range forms {
				if strings.ToUpper(form.Method) != "POST" || len(form.Inputs) == 0 {
					continue
				}

				targetURL := ctx.FinalURL.String()
				if form.ActionURL != "" {
					if actionURL, err := url.Parse(form.ActionURL); err == nil {
						targetURL = ctx.FinalURL.ResolveReference(actionURL).String()
					}
				}

				for _, in := range form.Inputs {
					nameLower := strings.ToLower(in.Name)
					if !strings.Contains(nameLower, "url") && !strings.Contains(nameLower, "uri") &&
						!strings.Contains(nameLower, "link") && !strings.Contains(nameLower, "callback") {
						continue
					}

					formValues := url.Values{}
					for _, input := range form.Inputs {
						if input.Name == in.Name {
							formValues.Set(input.Name, callbackURL)
						} else {
							formValues.Set(input.Name, input.Value)
						}
					}

					req, err := http.NewRequest("POST", targetURL, strings.NewReader(formValues.Encode()))
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

					resp, err := ctx.HTTPClient.Do(req)
					if err != nil {
						continue
					}
					bodyBytes, _ := engine.DecodeResponseBody(resp)
					bodyString := string(bodyBytes)
					resp.Body.Close()

					if ok, evidence := detectExternalFetchSignal(bodyString, baselineBody, callbackURL); ok {
						msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
						findings = append(findings, report.Finding{
							ID:                         "SSRF_CALLBACK_DETECTED",
							Category:                   string(checks.CategorySSRF),
							Severity:                   report.SeverityInfo,
							Confidence:                 report.ConfidenceLow,
							Title:                      msg.Title,
							Message:                    fmt.Sprintf(msg.Message, in.Name+" (POST)"),
							Evidence:                   fmt.Sprintf("%s; formAction=%s; field=%s; status=%d", evidence, targetURL, in.Name, resp.StatusCode),
							Fix:                        msg.Fix,
							IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}

func isSSRFParamCandidate(name, value string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	v := strings.ToLower(strings.TrimSpace(value))
	if n == "" {
		return false
	}
	keywords := []string{"url", "uri", "link", "callback", "redirect", "next", "dest", "endpoint", "path", "return"}
	for _, kw := range keywords {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "//")
}

func detectExternalFetchSignal(body, baseline, injectedURL string) (bool, string) {
	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baseline)
	injectedLower := strings.ToLower(injectedURL)

	markers := []string{
		"<h1>example domain</h1>",
		"iana.org/domains/example",
		"this domain is for use in documentation",
	}

	markerHit := ""
	for _, marker := range markers {
		if strings.Contains(bodyLower, marker) && !strings.Contains(baselineLower, marker) {
			markerHit = marker
			break
		}
	}
	if markerHit == "" {
		// Fallback: response includes injected host/url while baseline does not.
		if !(strings.Contains(bodyLower, "example.com") && !strings.Contains(baselineLower, "example.com")) &&
			!(strings.Contains(bodyLower, injectedLower) && !strings.Contains(baselineLower, injectedLower)) {
			return false, ""
		}
	}

	// Require meaningful response change to avoid reflection-only false positives.
	sim := similarityScore(bodyLower, baselineLower)
	if sim > 0.95 {
		return false, ""
	}

	if markerHit != "" {
		return true, fmt.Sprintf("Response contained external content marker '%s' after injecting '%s' (similarity %.2f)", markerHit, injectedURL, sim)
	}
	return true, fmt.Sprintf("Response changed and included external URL/host after injecting '%s' (similarity %.2f)", injectedURL, sim)
}

func similarityScore(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
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
