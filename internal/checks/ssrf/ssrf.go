package ssrf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/signal"
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

var metadataTargets = []struct {
	URL        string
	Markers    []string
	CloudLabel string
}{
	{
		URL:        "http://169.254.169.254/latest/meta-data/",
		Markers:    []string{"instance-id", "ami-id", "security-credentials", "meta-data"},
		CloudLabel: "AWS IMDS",
	},
	{
		URL:        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Markers:    []string{"compute", "vmid", "subscriptionid", "network"},
		CloudLabel: "Azure Metadata",
	},
	{
		URL:        "http://metadata.google.internal/computeMetadata/v1/",
		Markers:    []string{"metadata-flavor", "instance", "project"},
		CloudLabel: "GCP Metadata",
	},
}

func isExampleDomainResponse(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "<h1>example domain</h1>") &&
		(strings.Contains(l, "iana.org/domains/example") || strings.Contains(l, "this domain is for use in documentation"))
}

func CheckSSRF(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return checkSSRFPassive(ctx), nil
	}

	callbackURL := "http://example.com"
	verifyCallbackURL := "http://example.org"

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

			req, err := newScanRequest(ctx, http.MethodGet, requestURL, nil)
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
				verifyParams := url.Values{}
				for k, v := range queryParams {
					verifyParams[k] = v
				}
				verifyParams.Set(param, verifyCallbackURL)
				u.RawQuery = verifyParams.Encode()
				verifyReqURL := u.String()
				verifyReq, err := newScanRequest(ctx, http.MethodGet, verifyReqURL, nil)
				if err != nil {
					continue
				}
				verifyResp, err := ctx.HTTPClient.Do(verifyReq)
				if err != nil {
					continue
				}
				verifyBodyBytes, _ := engine.DecodeResponseBody(verifyResp)
				verifyBody := string(verifyBodyBytes)
				verifyResp.Body.Close()
				verifyOK, verifyEvidence := detectExternalFetchSignal(verifyBody, baselineBody, verifyCallbackURL)

				msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
				conf := report.ConfidenceLow
				validation := report.ValidationProbable
				sev := report.SeverityInfo
				fp := msg.IsPotentiallyFalsePositive
				if verifyOK {
					conf = report.ConfidenceMedium
					validation = report.ValidationConfirmed
					sev = report.SeverityMedium
					fp = false
					evidence = evidence + "; " + verifyEvidence
				}
				findings = append(findings, report.Finding{
					ID:                         "SSRF_CALLBACK_DETECTED",
					Category:                   string(checks.CategorySSRF),
					Severity:                   sev,
					Confidence:                 conf,
					Validation:                 validation,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, param),
					Evidence:                   fmt.Sprintf("%s; request=%s; status=%d", evidence, requestURL, resp.StatusCode),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: fp,
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

				reqLocal, err := newScanRequest(ctx, http.MethodGet, localRequestURL, nil)
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

			// Check Cloud Metadata Access Signals
			for _, mt := range metadataTargets {
				metaParams := url.Values{}
				for k, v := range queryParams {
					metaParams[k] = v
				}
				metaParams.Set(param, mt.URL)
				u.RawQuery = metaParams.Encode()
				metaRequestURL := u.String()

				reqMeta, err := newScanRequest(ctx, http.MethodGet, metaRequestURL, nil)
				if err != nil {
					continue
				}
				respMeta, err := ctx.HTTPClient.Do(reqMeta)
				if err != nil {
					continue
				}
				metaBytes, _ := engine.DecodeResponseBody(respMeta)
				metaBody := string(metaBytes)
				respMeta.Body.Close()

				if ok, evidence := detectMarkerSignal(metaBody, baselineBody, mt.Markers); ok {
					msg := msges.GetMessage("SSRF_LOCAL_ACCESS_DETECTED")
					findings = append(findings, report.Finding{
						ID:                         "SSRF_CLOUD_METADATA_ACCESS_DETECTED",
						Category:                   string(checks.CategorySSRF),
						Severity:                   report.SeverityHigh,
						Confidence:                 report.ConfidenceMedium,
						Validation:                 report.ValidationProbable,
						Title:                      "SSRF Cloud Metadata Access Signal",
						Message:                    fmt.Sprintf("Potential SSRF access to %s through parameter '%s'.", mt.CloudLabel, param),
						Evidence:                   fmt.Sprintf("%s; injected=%s; request=%s; status=%d", evidence, mt.URL, metaRequestURL, respMeta.StatusCode),
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: true,
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

					req, err := newScanRequest(ctx, http.MethodPost, targetURL, strings.NewReader(formValues.Encode()))
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
						verifyValues := url.Values{}
						for _, input := range form.Inputs {
							if input.Name == in.Name {
								verifyValues.Set(input.Name, verifyCallbackURL)
							} else {
								verifyValues.Set(input.Name, input.Value)
							}
						}
						verifyReq, err := newScanRequest(ctx, http.MethodPost, targetURL, strings.NewReader(verifyValues.Encode()))
						if err != nil {
							continue
						}
						verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						verifyResp, err := ctx.HTTPClient.Do(verifyReq)
						if err != nil {
							continue
						}
						verifyBodyBytes, _ := engine.DecodeResponseBody(verifyResp)
						verifyBody := string(verifyBodyBytes)
						verifyResp.Body.Close()
						verifyOK, verifyEvidence := detectExternalFetchSignal(verifyBody, baselineBody, verifyCallbackURL)

						msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
						conf := report.ConfidenceLow
						validation := report.ValidationProbable
						sev := report.SeverityInfo
						fp := msg.IsPotentiallyFalsePositive
						if verifyOK {
							conf = report.ConfidenceMedium
							validation = report.ValidationConfirmed
							sev = report.SeverityMedium
							fp = false
							evidence = evidence + "; " + verifyEvidence
						}
						findings = append(findings, report.Finding{
							ID:                         "SSRF_CALLBACK_DETECTED",
							Category:                   string(checks.CategorySSRF),
							Severity:                   sev,
							Confidence:                 conf,
							Validation:                 validation,
							Title:                      msg.Title,
							Message:                    fmt.Sprintf(msg.Message, in.Name+" (POST)"),
							Evidence:                   fmt.Sprintf("%s; formAction=%s; field=%s; status=%d", evidence, targetURL, in.Name, resp.StatusCode),
							Fix:                        msg.Fix,
							IsPotentiallyFalsePositive: fp,
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}

func CheckSSRFPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	return checkSSRFPassive(ctx), nil
}

func checkSSRFPassive(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx == nil || ctx.FinalURL == nil {
		return findings
	}

	var signals []string
	var riskyValueSignals []string
	var unsafeSchemeSignals []string

	// URL query-based indicators
	query := ctx.FinalURL.Query()
	for param, values := range query {
		v := ""
		if len(values) > 0 {
			v = values[0]
		}
		if isSSRFParamCandidate(param, v) {
			signals = append(signals, "query:"+param)
		}
		if isInternalLikeSSRFValue(v) {
			riskyValueSignals = append(riskyValueSignals, "query:"+param)
		}
		if isUnsafeSSRFScheme(v) {
			unsafeSchemeSignals = append(unsafeSchemeSignals, "query:"+param)
		}
	}

	// HTML form indicators from current response body (no extra request)
	if ctx.Response != nil && strings.Contains(strings.ToLower(ctx.Response.Header.Get("Content-Type")), "text/html") && len(ctx.BodyBytes) > 0 {
		doc, err := html.Parse(bytes.NewReader(ctx.BodyBytes))
		if err == nil {
			forms := crawler.ExtractForms(doc)
			for _, form := range forms {
				for _, in := range form.Inputs {
					if isSSRFParamCandidate(in.Name, in.Value) {
						signals = append(signals, "form:"+in.Name)
					}
					if isInternalLikeSSRFValue(in.Value) {
						riskyValueSignals = append(riskyValueSignals, "form:"+in.Name)
					}
					if isUnsafeSSRFScheme(in.Value) {
						unsafeSchemeSignals = append(unsafeSchemeSignals, "form:"+in.Name)
					}
				}
			}
		}
	}

	if len(signals) == 0 {
		return findings
	}

	findings = append(findings, report.Finding{
		ID:                         "SSRF_PASSIVE_INDICATOR",
		Category:                   string(checks.CategorySSRF),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      "SSRF Candidate Parameters Found (Passive Indicator)",
		Message:                    "Potential SSRF-related parameters were detected in URL/form fields. Manual validation is recommended.",
		Evidence:                   fmt.Sprintf("Indicators: %s", strings.Join(signals, ", ")),
		Fix:                        "Validate and restrict outbound request destinations (allowlist scheme/host/IP), block internal address ranges, and disable unsafe redirects.",
		IsPotentiallyFalsePositive: true,
	})

	if len(riskyValueSignals) > 0 {
		findings = append(findings, report.Finding{
			ID:                         "SSRF_INTERNAL_TARGET_IN_INPUT",
			Category:                   string(checks.CategorySSRF),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      "Internal/Metadata SSRF Target in Input",
			Message:                    "Request parameters already contain internal network or metadata-service style addresses. This raises SSRF exposure risk.",
			Evidence:                   fmt.Sprintf("Indicators: %s", strings.Join(uniqueStrings(riskyValueSignals), ", ")),
			Fix:                        "Deny private/link-local/localhost destinations and enforce strict outbound destination allowlisting.",
			IsPotentiallyFalsePositive: true,
		})
	}

	if len(unsafeSchemeSignals) > 0 {
		findings = append(findings, report.Finding{
			ID:                         "SSRF_UNSAFE_SCHEME_IN_INPUT",
			Category:                   string(checks.CategorySSRF),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceMedium,
			Title:                      "Unsafe URL Scheme in Input",
			Message:                    "Potentially dangerous URL scheme detected in request input (e.g., file://, gopher://).",
			Evidence:                   fmt.Sprintf("Indicators: %s", strings.Join(uniqueStrings(unsafeSchemeSignals), ", ")),
			Fix:                        "Allow only http/https schemes and reject file/gopher/dict/ftp/mailto/data schemes for outbound fetch parameters.",
			IsPotentiallyFalsePositive: true,
		})
	}

	return findings
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

func detectMarkerSignal(body, baseline string, markers []string) (bool, string) {
	bodyLower := strings.ToLower(body)
	baseLower := strings.ToLower(baseline)
	for _, m := range markers {
		lm := strings.ToLower(m)
		if strings.Contains(bodyLower, lm) && !strings.Contains(baseLower, lm) {
			sim := similarityScore(bodyLower, baseLower)
			if sim <= 0.95 {
				return true, fmt.Sprintf("marker '%s' detected (similarity %.2f)", m, sim)
			}
		}
	}
	return false, ""
}

func isInternalLikeSSRFValue(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	internalHints := []string{
		"127.0.0.1", "localhost", "::1", "0.0.0.0",
		"169.254.169.254", "metadata.google.internal",
		"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "192.168.",
	}
	for _, h := range internalHints {
		if strings.Contains(v, h) {
			return true
		}
	}
	return false
}

func isUnsafeSSRFScheme(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	schemes := []string{"file://", "gopher://", "dict://", "ftp://", "mailto:", "data:"}
	for _, s := range schemes {
		if strings.HasPrefix(v, s) {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func similarityScore(a, b string) float64 {
	a = signal.NormalizeForDiff(a)
	b = signal.NormalizeForDiff(b)

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

func newScanRequest(scanCtx *ctxpkg.Context, method, target string, body io.Reader) (*http.Request, error) {
	if scanCtx != nil && scanCtx.RequestContext != nil {
		return http.NewRequestWithContext(scanCtx.RequestContext, method, target, body)
	}
	return http.NewRequest(method, target, body)
}
