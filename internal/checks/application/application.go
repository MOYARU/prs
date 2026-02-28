package application

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/signal"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var idorSensitiveFieldRegex = regexp.MustCompile(`(?i)"?(user_id|userid|account_id|account|customer_id|email|username|role|member_id|profile_id)"?\s*[:=]\s*"?([a-zA-Z0-9@._-]{1,80})"?`)

func CheckApplicationSecurity(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Input reflection probe sends an extra request, so keep it active-only.
	if ctx.Mode == ctxpkg.Active {
		findings = append(findings, checkInputReflection(ctx)...)
	}
	findings = append(findings, checkCSRFTokenPresence(ctx)...)

	if ctx.Mode == ctxpkg.Active {
		findings = append(findings, checkGraphQLIntrospection(ctx)...)
		findings = append(findings, checkOpenRedirect(ctx)...)
	}

	return findings, nil
}

// CheckIDORPassive runs a non-intrusive IDOR indicator check without sending extra requests.
func CheckIDORPassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.FinalURL == nil {
		return findings, nil
	}

	numericIDs := collectNumericIDCandidates(ctx.FinalURL)
	if len(numericIDs) == 0 {
		return findings, nil
	}

	sensitive := extractSensitiveValues(string(ctx.BodyBytes))
	if len(sensitive) == 0 {
		return findings, nil
	}

	msg := msges.GetMessage("IDOR_RESOURCE_GUESSING")
	findings = append(findings, report.Finding{
		ID:                         "IDOR_PASSIVE_INDICATOR",
		Category:                   string(checks.CategoryAccessControl),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      "IDOR Passive Indicator",
		Message:                    fmt.Sprintf("Numeric resource identifiers detected (%s) with user-related fields in response. Manual authorization review recommended.", strings.Join(numericIDs, ", ")),
		Evidence:                   fmt.Sprintf("URL=%s, sensitive_fields=%d", ctx.FinalURL.String(), len(sensitive)),
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: true,
	})

	return findings, nil
}

// CheckIDORActive runs a low-impact active verification using only +/-1 ID mutations.
func CheckIDORActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil || ctx.Response == nil {
		return findings, nil
	}
	if len(ctx.BodyBytes) == 0 {
		return findings, nil
	}

	originalURL := ctx.FinalURL.String()
	originalStatus := ctx.Response.StatusCode
	originalBody := ctx.BodyBytes

	testURLs := buildLowImpactIDORTestURLs(ctx.FinalURL)
	for _, testURL := range testURLs {
		findings = append(findings, probeIDORAgainstBaseline(ctx, originalURL, originalStatus, originalBody, testURL)...)
	}

	return findings, nil
}

func checkInputReflection(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding

	testString := "PRS_" + generateRandomString(12)
	originalURL := ctx.FinalURL.String()

	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return findings
	}
	query := parsedURL.Query()
	query.Set("prs_test_param", testString)
	parsedURL.RawQuery = query.Encode()

	testURL := parsedURL.String()

	req, err := newScanRequest(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return findings
	}

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := engine.DecodeResponseBody(resp)
		if err != nil {
			return findings
		}
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, testString) {
			msg := msges.GetMessage("INPUT_REFLECTION_DETECTED")
			findings = append(findings, report.Finding{
				ID:                         "INPUT_REFLECTION_DETECTED",
				Category:                   string(checks.CategoryInputHandling),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, "prs_test_param"),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}
	return findings
}

func probeIDORAgainstBaseline(ctx *ctxpkg.Context, originalURL string, originalStatus int, originalBody []byte, testURL string) []report.Finding {
	var findings []report.Finding

	// Fetch the test URL
	reqTest, err := newScanRequest(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return findings
	}
	testResp, err := ctx.HTTPClient.Do(reqTest)
	if err != nil {
		return findings
	}
	defer testResp.Body.Close()
	testBody, _ := engine.DecodeResponseBody(testResp)

	if originalStatus == http.StatusOK && testResp.StatusCode == http.StatusOK {
		originalText := ExtractTextFromHTML(originalBody)
		testText := ExtractTextFromHTML(testBody)
		similarity := CalculateTextSimilarity(originalText, testText)
		sensitiveChanged, sensitiveEvidence := detectSensitiveDataChange(originalBody, testBody)
		sizeDiff := absInt(len(originalBody) - len(testBody))

		// Stronger signal: meaningful content shift plus identity-related data change.
		if len(originalBody) > 0 && len(testBody) > 0 && (sensitiveChanged || (similarity < 0.60 && sizeDiff > 200)) {
			msg := msges.GetMessage("IDOR_POSSIBLE")
			evidence := fmt.Sprintf(
				"original=%s (status=%d), test=%s (status=%d), similarity=%.2f, sizeDiff=%d",
				originalURL, originalStatus, testURL, testResp.StatusCode, similarity, sizeDiff,
			)
			if sensitiveEvidence != "" {
				evidence = evidence + ", " + sensitiveEvidence
			}
			findings = append(findings, report.Finding{
				ID:                         "IDOR_POSSIBLE",
				Category:                   string(checks.CategoryAccessControl),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf("Authorization boundary may be bypassed by changing identifier: %s", testURL),
				Evidence:                   evidence,
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	} else if testResp.StatusCode == http.StatusOK &&
		(originalStatus == http.StatusNotFound || originalStatus == http.StatusForbidden || originalStatus == http.StatusUnauthorized) {
		msg := msges.GetMessage("IDOR_RESOURCE_GUESSING")
		findings = append(findings, report.Finding{
			ID:                         "IDOR_RESOURCE_GUESSING",
			Category:                   string(checks.CategoryAccessControl),
			Severity:                   report.SeverityMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf("Status changed after low-impact ID mutation: %s", testURL),
			Evidence:                   fmt.Sprintf("original=%s (status=%d), test=%s (status=%d)", originalURL, originalStatus, testURL, testResp.StatusCode),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings
}

func buildLowImpactIDORTestURLs(base *url.URL) []string {
	tests := make([]string, 0, 6)
	seen := make(map[string]bool)

	pathSegments := strings.Split(base.Path, "/")
	for i, segment := range pathSegments {
		id, err := strconv.Atoi(segment)
		if err != nil || id < 1 {
			continue
		}
		candidates := []int{id + 1}
		if id > 1 {
			candidates = append(candidates, id-1)
		}
		for _, cand := range candidates {
			segCopy := append([]string(nil), pathSegments...)
			segCopy[i] = strconv.Itoa(cand)
			u := *base
			u.Path = strings.Join(segCopy, "/")
			s := u.String()
			if !seen[s] {
				seen[s] = true
				tests = append(tests, s)
			}
		}
	}

	query := base.Query()
	for param, values := range query {
		if len(values) != 1 {
			continue
		}
		id, err := strconv.Atoi(values[0])
		if err != nil || id < 1 {
			continue
		}
		candidates := []int{id + 1}
		if id > 1 {
			candidates = append(candidates, id-1)
		}
		for _, cand := range candidates {
			newQuery := url.Values{}
			for k, v := range query {
				newQuery[k] = v
			}
			newQuery.Set(param, strconv.Itoa(cand))
			u := *base
			u.RawQuery = newQuery.Encode()
			s := u.String()
			if !seen[s] {
				seen[s] = true
				tests = append(tests, s)
			}
		}
	}

	if len(tests) > 6 {
		tests = tests[:6]
	}
	return tests
}

func collectNumericIDCandidates(u *url.URL) []string {
	var ids []string
	pathSegments := strings.Split(u.Path, "/")
	for _, segment := range pathSegments {
		if _, err := strconv.Atoi(segment); err == nil {
			ids = append(ids, "path:"+segment)
		}
	}
	for param, values := range u.Query() {
		if len(values) == 1 {
			if _, err := strconv.Atoi(values[0]); err == nil {
				ids = append(ids, "query:"+param+"="+values[0])
			}
		}
	}
	if len(ids) > 5 {
		ids = ids[:5]
	}
	return ids
}

func checkCSRFTokenPresence(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding

	if ctx.Response.StatusCode != http.StatusOK || ctx.Response.Header.Get("Content-Type") == "" || !strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		return findings
	}

	if len(ctx.BodyBytes) == 0 {
		return findings
	}
	bodyString := string(ctx.BodyBytes)

	if strings.Contains(strings.ToLower(bodyString), "<form") {
		hasCSRFToken := strings.Contains(strings.ToLower(bodyString), "csrf_token") ||
			strings.Contains(strings.ToLower(bodyString), "authenticity_token") ||
			strings.Contains(strings.ToLower(bodyString), "_token") ||
			strings.Contains(strings.ToLower(bodyString), "csrf-token") // Meta tag check

		if !hasCSRFToken {
			msg := msges.GetMessage("CSRF_TOKEN_POSSIBLY_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "CSRF_TOKEN_POSSIBLY_MISSING",
				Category:                   string(checks.CategoryAccessControl),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    msg.Message,
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	return findings
}

func checkGraphQLIntrospection(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx.Mode == ctxpkg.Passive {
		return findings
	}

	introspectionQuery := `{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{name description type{...TypeRef}defaultValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"}`
	graphqlPaths := []string{"/graphql", "/api/graphql", "/graph"}

	for _, path := range graphqlPaths {
		targetURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + path

		req, err := newScanRequest(ctx, http.MethodPost, targetURL, strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, err := engine.DecodeResponseBody(resp)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyString := string(bodyBytes)

			if strings.Contains(bodyString, "__schema") && strings.Contains(bodyString, "queryType") && strings.Contains(bodyString, "fields") {
				msg := msges.GetMessage("GRAPHQL_INTROSPECTION_ENABLED")
				findings = append(findings, report.Finding{
					ID:                         "GRAPHQL_INTROSPECTION_ENABLED",
					Category:                   string(checks.CategoryAPI),
					Severity:                   report.SeverityMedium,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, path),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
				return findings
			}
		}
	}
	return findings
}

func checkOpenRedirect(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding

	targetDomains := []string{"example.com", "example.org"}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()
	confirmedByParam := make(map[string]map[string]bool)

	for param := range queryParams {
		for _, domain := range targetDomains {
			payloads := []string{
				"https://" + domain,
				"//" + domain,
				"/\\" + domain,
			}
			for _, payload := range payloads {
				newParams := url.Values{}
				for k, v := range queryParams {
					newParams[k] = v
				}
				newParams.Set(param, payload)
				u.RawQuery = newParams.Encode()

				req, err := newScanRequest(ctx, http.MethodGet, u.String(), nil)
				if err != nil {
					continue
				}

				// Don't follow redirects automatically to check the Location header
				resp, err := ctx.HTTPClient.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					loc := strings.TrimSpace(resp.Header.Get("Location"))
					if redirectsToInjectedHost(loc, domain, ctx.FinalURL) {
						if confirmedByParam[param] == nil {
							confirmedByParam[param] = make(map[string]bool)
						}
						confirmedByParam[param][domain] = true
					}
				}
				resp.Body.Close()
			}
		}

		// Additional high-risk scheme checks.
		for _, payload := range []string{"javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="} {
			newParams := url.Values{}
			for k, v := range queryParams {
				newParams[k] = v
			}
			newParams.Set(param, payload)
			u.RawQuery = newParams.Encode()
			req, err := newScanRequest(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				continue
			}
			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Location")))
				if strings.HasPrefix(loc, "javascript:") || strings.HasPrefix(loc, "data:") {
					msg := msges.GetMessage("OPEN_REDIRECT_DETECTED")
					findings = append(findings, report.Finding{
						ID:                         "OPEN_REDIRECT_SCRIPT_SCHEME",
						Category:                   string(checks.CategoryAppLogic),
						Severity:                   report.SeverityHigh,
						Confidence:                 report.ConfidenceHigh,
						Validation:                 report.ValidationConfirmed,
						Title:                      msg.Title + " (Script Scheme)",
						Message:                    fmt.Sprintf("Redirect parameter %q accepted script/data scheme payload.", param),
						Evidence:                   fmt.Sprintf("Location=%q", resp.Header.Get("Location")),
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: false,
					})
				}
			}
			resp.Body.Close()
		}
	}

	for param, domains := range confirmedByParam {
		msg := msges.GetMessage("OPEN_REDIRECT_DETECTED")
		if len(domains) >= 2 {
			findings = append(findings, report.Finding{
				ID:                         "OPEN_REDIRECT_DETECTED",
				Category:                   string(checks.CategoryAppLogic),
				Severity:                   report.SeverityHigh,
				Confidence:                 report.ConfidenceHigh,
				Validation:                 report.ValidationConfirmed,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, param, "multiple external domains"),
				Evidence:                   fmt.Sprintf("Parameter %q redirected to multiple injected hosts: %s", param, mapKeys(domains)),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: false,
			})
			continue
		}
		findings = append(findings, report.Finding{
			ID:                         "OPEN_REDIRECT_DETECTED",
			Category:                   string(checks.CategoryAppLogic),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceMedium,
			Validation:                 report.ValidationProbable,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, param, mapKeys(domains)),
			Evidence:                   fmt.Sprintf("Parameter %q redirected to injected host: %s", param, mapKeys(domains)),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: true,
		})
	}
	return findings
}

func redirectsToInjectedHost(locationHeader, expectedHost string, base *url.URL) bool {
	if locationHeader == "" {
		return false
	}
	loc, err := url.Parse(locationHeader)
	if err != nil {
		return false
	}
	if base != nil {
		loc = base.ResolveReference(loc)
	}
	if loc == nil || loc.Hostname() == "" {
		return false
	}
	return strings.EqualFold(loc.Hostname(), expectedHost)
}

func mapKeys(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ",")
}

func newScanRequest(scanCtx *ctxpkg.Context, method, target string, body io.Reader) (*http.Request, error) {
	if scanCtx != nil && scanCtx.RequestContext != nil {
		return http.NewRequestWithContext(scanCtx.RequestContext, method, target, body)
	}
	return http.NewRequest(method, target, body)
}
func ExtractTextFromHTML(body []byte) string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return ""
	}

	var buf strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if len(text) > 0 {
				buf.WriteString(text)
				buf.WriteString(" ")
			}
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "head", "noscript", "iframe":
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return strings.TrimSpace(buf.String())
}

func CalculateTextSimilarity(text1, text2 string) float64 {
	text1 = signal.NormalizeForDiff(text1)
	text2 = signal.NormalizeForDiff(text2)

	words1 := strings.Fields(strings.ToLower(text1))
	words2 := strings.Fields(strings.ToLower(text2))

	if len(words1) == 0 && len(words2) == 0 {
		return 1.0
	}
	if len(words1) == 0 || len(words2) == 0 {
		return 0.0
	}

	freq1 := make(map[string]int)
	for _, word := range words1 {
		freq1[word]++
	}

	freq2 := make(map[string]int)
	for _, word := range words2 {
		freq2[word]++
	}

	intersection := 0
	for word, count := range freq1 {
		if freq2[word] > 0 {
			intersection += int(math.Min(float64(count), float64(freq2[word])))
		}
	}

	union := len(words1) + len(words2) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

func IsErrorPage(body string, status int) bool {
	// Common error status codes
	if status >= 400 && status < 500 && status != http.StatusOK && status != http.StatusFound && status != http.StatusForbidden {
		return true
	}

	lowerBody := strings.ToLower(body)
	errorKeywords := []string{"not found", "404", "exception", "unauthorized", "forbidden"}
	for _, keyword := range errorKeywords {
		if strings.Contains(lowerBody, keyword) {
			return true
		}
	}
	return false
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "fallback"
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes)
}

func detectSensitiveDataChange(originalBody, testBody []byte) (bool, string) {
	orig := extractSensitiveValues(string(originalBody))
	test := extractSensitiveValues(string(testBody))

	for key, originalValue := range orig {
		if testValue, ok := test[key]; ok && testValue != originalValue {
			return true, fmt.Sprintf("%s changed (%s -> %s)", key, originalValue, testValue)
		}
	}
	return false, ""
}

func extractSensitiveValues(body string) map[string]string {
	out := make(map[string]string)
	matches := idorSensitiveFieldRegex.FindAllStringSubmatch(body, 20)
	for _, m := range matches {
		if len(m) >= 3 {
			key := strings.ToLower(strings.TrimSpace(m[1]))
			val := strings.TrimSpace(m[2])
			if key != "" && val != "" {
				out[key] = val
			}
		}
	}
	return out
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
