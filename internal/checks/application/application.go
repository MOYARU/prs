package application

import (
	"crypto/rand"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
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
	if ctx.Mode == ctxpkg.Active {
		findings = append(findings, checkIDOR(ctx)...)
	}
	findings = append(findings, checkCSRFTokenPresence(ctx)...)

	if ctx.Mode == ctxpkg.Active {
		findings = append(findings, checkGraphQLIntrospection(ctx)...)
		findings = append(findings, checkOpenRedirect(ctx)...)
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

	req, err := http.NewRequest("GET", testURL, nil)
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

func checkIDOR(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	var originalURL string
	originalURL = ctx.FinalURL.String()

	pathSegments := strings.Split(ctx.FinalURL.Path, "/")
	for i, segment := range pathSegments {
		if id, err := strconv.Atoi(segment); err == nil && id > 1 {
			testPath := strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(id-1) + strings.Join(pathSegments[i+1:], "/")
			var testURL string
			testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath
			msg := msges.GetMessage("IDOR_POSSIBLE")
			findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id-1), msg.IsPotentiallyFalsePositive)...)

			// Try incrementing
			testPath = strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(id+1) + strings.Join(pathSegments[i+1:], "/")
			testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath // Re-assign
			msg = msges.GetMessage("IDOR_POSSIBLE")
			findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id+1), msg.IsPotentiallyFalsePositive)...)

			// Try random ID
			randID := 1000 + int(id)%500
			testPath = strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(randID) + strings.Join(pathSegments[i+1:], "/")
			testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath
			msg = msges.GetMessage("IDOR_POSSIBLE")
			findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, randID), msg.IsPotentiallyFalsePositive)...)
		}
	}

	query := ctx.FinalURL.Query()
	for param, values := range query {
		if len(values) == 1 {
			if id, err := strconv.Atoi(values[0]); err == nil && id > 1 {
				// Try decrementing
				newQuery := url.Values{}
				for k, v := range query {
					newQuery[k] = v
				}
				newQuery.Set(param, strconv.Itoa(id-1))
				testURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + ctx.FinalURL.Path + "?" + newQuery.Encode()
				msg := msges.GetMessage("IDOR_POSSIBLE") // Assuming IDOR_POSSIBLE has format string
				findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id-1), msg.IsPotentiallyFalsePositive)...)

				// Try incrementing
				newQuery.Set(param, strconv.Itoa(id+1))
				testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + ctx.FinalURL.Path + "?" + newQuery.Encode()
				msg = msges.GetMessage("IDOR_POSSIBLE") // Assuming IDOR_POSSIBLE has format string
				findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id+1), msg.IsPotentiallyFalsePositive)...)

				// Try random ID
				newQuery.Set(param, strconv.Itoa(id+100))
				testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + ctx.FinalURL.Path + "?" + newQuery.Encode()
				msg = msges.GetMessage("IDOR_POSSIBLE")
				findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id+100), msg.IsPotentiallyFalsePositive)...)
			}
		}
	}

	return findings
}

func probeIDOR(ctx *ctxpkg.Context, originalURL, testURL, description string, isPotentiallyFalsePositive bool) []report.Finding {
	var findings []report.Finding

	// Fetch the original URL to compare response size/content
	reqOrig, err := http.NewRequest("GET", originalURL, nil)
	if err != nil {
		return findings
	}
	originalResp, err := ctx.HTTPClient.Do(reqOrig)
	if err != nil {
		return findings
	}
	defer originalResp.Body.Close()
	originalBody, _ := engine.DecodeResponseBody(originalResp)

	// Fetch the test URL
	reqTest, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return findings
	}
	testResp, err := ctx.HTTPClient.Do(reqTest)
	if err != nil {
		return findings
	}
	defer testResp.Body.Close()
	testBody, _ := engine.DecodeResponseBody(testResp)

	if originalResp.StatusCode == http.StatusOK && testResp.StatusCode == http.StatusOK {
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
				originalURL, originalResp.StatusCode, testURL, testResp.StatusCode, similarity, sizeDiff,
			)
			if sensitiveEvidence != "" {
				evidence = evidence + ", " + sensitiveEvidence
			}
			findings = append(findings, report.Finding{
				ID:                         "IDOR_POSSIBLE",
				Category:                   string(checks.CategoryAccessControl),
				Severity:                   report.SeverityHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, description),
				Evidence:                   evidence,
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	} else if testResp.StatusCode == http.StatusOK &&
		(originalResp.StatusCode == http.StatusNotFound || originalResp.StatusCode == http.StatusForbidden || originalResp.StatusCode == http.StatusUnauthorized) {
		msg := msges.GetMessage("IDOR_RESOURCE_GUESSING")
		findings = append(findings, report.Finding{
			ID:                         "IDOR_RESOURCE_GUESSING",
			Category:                   string(checks.CategoryAccessControl),
			Severity:                   report.SeverityMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, description),
			Evidence:                   fmt.Sprintf("original=%s (status=%d), test=%s (status=%d)", originalURL, originalResp.StatusCode, testURL, testResp.StatusCode),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings
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

		req, err := http.NewRequest("POST", targetURL, strings.NewReader(introspectionQuery))
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

	targetDomain := "example.com"
	payloads := []string{
		"http://" + targetDomain,
		"//" + targetDomain,
		"/\\" + targetDomain,
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	for param := range queryParams {
		for _, payload := range payloads {
			newParams := url.Values{}
			for k, v := range queryParams {
				newParams[k] = v
			}
			newParams.Set(param, payload)
			u.RawQuery = newParams.Encode()

			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}

			// Don't follow redirects automatically to check the Location header
			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Header.Get("Location")
				if strings.Contains(loc, targetDomain) {
					msg := msges.GetMessage("OPEN_REDIRECT_DETECTED")
					findings = append(findings, report.Finding{
						ID:       "OPEN_REDIRECT_DETECTED",
						Category: string(checks.CategoryAppLogic),
						Severity: report.SeverityMedium,
						Title:    msg.Title,
						Message:  fmt.Sprintf(msg.Message, param, targetDomain),
						Fix:      msg.Fix,
					})
				}
			}
		}
	}
	return findings
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
