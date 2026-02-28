package web

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context" // New import with alias
	"github.com/MOYARU/prs/internal/config"
	msges "github.com/MOYARU/prs/internal/messages" // New import for messages
	"github.com/MOYARU/prs/internal/report"
)

var secretPatterns = []struct {
	Name         string
	Regex        *regexp.Regexp
	ValueGroup   int
	MinValueLen  int
	NeedEntropy  bool
	BlockUUIDVal bool
}{
	{Name: "AWS Access Key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), ValueGroup: 0, MinValueLen: 20},
	{Name: "Google/Firebase API Key", Regex: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), ValueGroup: 0, MinValueLen: 39},
	// Generic keys are high-noise, so require stronger shape and entropy.
	{Name: "Generic API Key", Regex: regexp.MustCompile(`(?i)(api_key|apikey|access_key|client_secret|secret_key|auth_token)\s*[:=]\s*['"]([A-Za-z0-9_\-]{24,})['"]`), ValueGroup: 2, MinValueLen: 24, NeedEntropy: true, BlockUUIDVal: true},
	{Name: "JWT Token", Regex: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}`), ValueGroup: 0, MinValueLen: 30, NeedEntropy: true},
	{Name: "Firebase Config API Key", Regex: regexp.MustCompile(`apiKey\s*:\s*['"]([^'"]+)['"]`), ValueGroup: 1, MinValueLen: 30, NeedEntropy: true},
}

var uuidLikeRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
var obviousPlaceholderRegex = regexp.MustCompile(`(?i)(example|sample|dummy|test|changeme|your[_-]?api[_-]?key|your[_-]?token|replace[_-]?me|placeholder|null|undefined|xxxx|todo|default)`)

func CheckWebContentExposure(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	var mu sync.Mutex

	// Active Checks: File probes
	if ctx.Mode == ctxpkg.Active {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10) // Limit concurrency

		probes := []struct {
			path     string
			msgID    string
			category checks.Category
		}{
			{"/robots.txt", "ROBOTS_TXT_EXPOSED", checks.CategoryFileExposure},
			{"/sitemap.xml", "SITEMAP_XML_EXPOSED", checks.CategoryFileExposure},
			{"/.well-known/security.txt", "SECURITY_TXT_EXPOSED", checks.CategoryFileExposure},
			{"/.well-known/", "WELL_KNOWN_EXPOSED", checks.CategoryFileExposure},
			{"/.git/HEAD", "GIT_HEAD_EXPOSED", checks.CategoryFileExposure},
			{"/.git/config", "GIT_CONFIG_EXPOSED", checks.CategoryFileExposure},
			{"/.env", "ENV_EXPOSED", checks.CategoryFileExposure},
			{"/.travis.yml", "TRAVIS_YML_EXPOSED", checks.CategoryFileExposure},
			{"/.gitlab-ci.yml", "GITLAB_CI_YML_EXPOSED", checks.CategoryFileExposure},
			{"/Jenkinsfile", "JENKINSFILE_EXPOSED", checks.CategoryFileExposure},
			{"/actuator", "ACTUATOR_ENDPOINT_EXPOSED", checks.CategoryInfrastructure},
			{"/debug", "DEBUG_ENDPOINT_EXPOSED", checks.CategoryInfrastructure},
		}

		// Backup files
		backupExtensions := []string{".bak", ".old", ".swp", "~"}
		path := ctx.FinalURL.Path
		if path != "" && path != "/" {
			for _, ext := range backupExtensions {
				probes = append(probes, struct {
					path, msgID string
					category    checks.Category
				}{path + ext, "BACKUP_FILE_EXPOSED", checks.CategoryFileExposure})
			}
		}

		for _, p := range probes {
			wg.Add(1)
			go func(p struct {
				path, msgID string
				category    checks.Category
			}) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				fs := checkPathExposure(ctx, p.path, p.msgID, p.category)
				if len(fs) > 0 {
					mu.Lock()
					findings = append(findings, fs...)
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
	}
	if ctx.Response != nil && ctx.Response.StatusCode == http.StatusOK {
		contentType := ctx.Response.Header.Get("Content-Type")
		bodyString := string(ctx.BodyBytes)

		if strings.Contains(contentType, "text/html") {
			// Parse HTML once and reuse the node tree
			doc, err := html.Parse(strings.NewReader(bodyString))
			if err == nil {
				findings = append(findings, checkMixedContent(ctx, doc)...)
				findings = append(findings, checkIframeSandbox(ctx, doc)...)
				findings = append(findings, checkInlineScripts(ctx, doc)...)
				findings = append(findings, checkSecrets(bodyString)...)
				findings = append(findings, checkConsoleUsage(bodyString)...)
			}
		} else if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "application/x-javascript") {
			findings = append(findings, checkSecrets(bodyString)...)
			findings = append(findings, checkConsoleUsage(bodyString)...)
		}
	}

	return findings, nil
}

func checkPathExposure(ctx *ctxpkg.Context, path string, msgID string, category checks.Category) []report.Finding {
	var findings []report.Finding
	lowerPath := strings.ToLower(path)
	if lowerPath == "/robots.txt" || lowerPath == "/sitemap.xml" || lowerPath == "/.well-known/security.txt" {
		return findings
	}
	targetURL := resolveRelativeURL(ctx.FinalURL, path)

	req, err := ctxpkg.NewRequest(ctx, "GET", targetURL.String(), nil)
	if err != nil {
		return findings
	}

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	body := string(bodyBytes)

	if resp.StatusCode == http.StatusOK && isLikelyExposedContent(path, body) {
		msg := msges.GetMessage(msgID)
		findings = append(findings, report.Finding{
			ID:                         strings.ReplaceAll(strings.ToUpper(path), "/", "_") + "_EXPOSED",
			Category:                   string(category),
			Severity:                   report.SeverityMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, path),
			Evidence:                   fmt.Sprintf("Path %s is accessible with status 200 OK.", path),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}
	return findings
}

func resolveRelativeURL(baseURL *url.URL, relativePath string) *url.URL {
	newURL, _ := url.Parse(relativePath)
	return baseURL.ResolveReference(newURL)
}

func isLikelyExposedContent(path, body string) bool {
	lowerPath := strings.ToLower(path)
	lowerBody := strings.ToLower(body)
	switch {
	case strings.HasSuffix(lowerPath, "/robots.txt"):
		return strings.Contains(lowerBody, "user-agent:")
	case strings.HasSuffix(lowerPath, "/sitemap.xml"):
		return strings.Contains(lowerBody, "<urlset") || strings.Contains(lowerBody, "<sitemapindex")
	case strings.HasSuffix(lowerPath, "/security.txt"):
		return strings.Contains(lowerBody, "contact:")
	case strings.Contains(lowerPath, ".git/head"):
		return strings.HasPrefix(strings.TrimSpace(lowerBody), "ref:")
	case strings.Contains(lowerPath, ".git/config"):
		return strings.Contains(lowerBody, "[core]")
	case strings.HasSuffix(lowerPath, "/.env"):
		return strings.Contains(body, "=")
	default:
		return len(strings.TrimSpace(body)) > 0
	}
}

func checkMixedContent(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	if ctx.FinalURL.Scheme != "https" {
		return findings
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrName := ""
			switch n.Data {
			case "script", "img", "audio", "video", "source", "embed", "track":
				attrName = "src"
			case "link":
				for _, a := range n.Attr {
					if a.Key == "rel" && (a.Val == "stylesheet" || a.Val == "preload") {
						attrName = "href"
						break
					}
				}
			}

			if attrName != "" {
				for _, a := range n.Attr {
					if a.Key == attrName {
						if strings.HasPrefix(a.Val, "http://") {
							msg := msges.GetMessage("MIXED_CONTENT_DETECTED")
							findings = append(findings, report.Finding{
								ID:                         "MIXED_CONTENT_DETECTED",
								Category:                   string(checks.CategoryClientSecurity),
								Severity:                   report.SeverityMedium,
								Title:                      msg.Title,
								Message:                    fmt.Sprintf(msg.Message, a.Val),
								Evidence:                   fmt.Sprintf("Insecure resource loaded: %s", a.Val),
								Fix:                        msg.Fix,
								IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
							})
							// Report only once per resource
							break
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return findings
}

func checkSecrets(content string) []report.Finding {
	var findings []report.Finding
	seen := make(map[string]struct{})
	policy := config.LoadScanPolicyFromPRS()
	entropyMin := policy.SecretsEntropyMin
	if entropyMin <= 0 {
		entropyMin = 3.2
	}

	for _, pattern := range secretPatterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			foundValue := match[0]
			if pattern.ValueGroup > 0 && len(match) > pattern.ValueGroup {
				foundValue = match[pattern.ValueGroup]
			}
			if !isLikelyLeakedSecret(foundValue, pattern.MinValueLen, pattern.NeedEntropy, pattern.BlockUUIDVal, entropyMin) {
				continue
			}

			key := pattern.Name + "|" + foundValue
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			displayValue := foundValue
			if len(foundValue) > 50 { // Truncate for display
				displayValue = foundValue[:47] + "..."
			}
			msg := msges.GetMessage("SENSITIVE_API_KEY_FOUND")
			findings = append(findings, report.Finding{
				ID:                         "SENSITIVE_API_KEY_FOUND",
				Category:                   string(checks.CategoryInformationLeakage),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceLow,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, pattern.Name, displayValue),
				Evidence:                   fmt.Sprintf("Pattern: %s, Value: %s", pattern.Name, displayValue),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}
	return findings
}

func isLikelyLeakedSecret(v string, minLen int, needEntropy bool, blockUUID bool, entropyMin float64) bool {
	value := strings.TrimSpace(v)
	if len(value) < minLen {
		return false
	}
	if obviousPlaceholderRegex.MatchString(value) {
		return false
	}
	if blockUUID && uuidLikeRegex.MatchString(value) {
		return false
	}
	if !needEntropy {
		return true
	}
	return hasReasonableSecretShape(value) && shannonEntropy(value) >= entropyMin
}

func hasReasonableSecretShape(v string) bool {
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	kinds := 0
	if hasLower {
		kinds++
	}
	if hasUpper {
		kinds++
	}
	if hasDigit {
		kinds++
	}
	if hasSymbol {
		kinds++
	}
	return kinds >= 2
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		p := c / n
		h -= p * (math.Log(p) / math.Log(2))
	}
	return h
}

func checkConsoleUsage(content string) []report.Finding {
	var findings []report.Finding
	if strings.Contains(content, "console.log") || strings.Contains(content, "console.debug") || strings.Contains(content, "console.error") {
		msg := msges.GetMessage("CONSOLE_LOG_EXPOSED")
		findings = append(findings, report.Finding{
			ID:                         "CONSOLE_LOG_EXPOSED",
			Category:                   string(checks.CategoryInformationLeakage),
			Severity:                   report.SeverityInfo,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, "console.* usage detected"),
			Evidence:                   "Found 'console.log', 'console.debug', or 'console.error' in response body.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}
	return findings
}

func checkIframeSandbox(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	total := 0
	sampleSrc := ""
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "iframe" {
			hasSandbox := false
			for _, a := range n.Attr {
				if a.Key == "sandbox" {
					hasSandbox = true
					break
				}
			}
			if !hasSandbox {
				src := ""
				for _, a := range n.Attr {
					if a.Key == "src" {
						src = a.Val
						break
					}
				}
				total++
				if sampleSrc == "" {
					sampleSrc = src
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	if total > 0 {
		msg := msges.GetMessage("IFRAME_SANDBOX_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "IFRAME_SANDBOX_MISSING",
			Category:                   string(checks.CategoryClientSecurity),
			Severity:                   report.SeverityMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, sampleSrc),
			Evidence:                   fmt.Sprintf("Found %d iframe tags without sandbox. Example src: %s", total, sampleSrc),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings
}

func checkInlineScripts(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	cspHeader := ctx.Response.Header.Get("Content-Security-Policy")
	hasStrictCSP := false
	if cspHeader != "" {
		if !strings.Contains(cspHeader, "'unsafe-inline'") &&
			!strings.Contains(cspHeader, "script-src *") &&
			!strings.Contains(cspHeader, "script-src 'self' 'unsafe-eval'") { // simplified check
			hasStrictCSP = true
		}
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			isInline := true
			for _, a := range n.Attr {
				if a.Key == "src" {
					isInline = false
					break
				}
			}
			if isInline && n.FirstChild != nil && strings.TrimSpace(n.FirstChild.Data) != "" {
				if !hasStrictCSP {
					msg := msges.GetMessage("INLINE_SCRIPT_DETECTED")
					findings = append(findings, report.Finding{
						ID:                         "INLINE_SCRIPT_DETECTED",
						Category:                   string(checks.CategoryClientSecurity),
						Severity:                   report.SeverityMedium,
						Title:                      msg.Title,
						Message:                    msg.Message,
						Evidence:                   "Inline <script> tag found without a strict CSP.",
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return findings
}
