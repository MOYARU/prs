package info

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/config"
	"github.com/MOYARU/prs/internal/report"
	"golang.org/x/net/publicsuffix"
)

var (
	absoluteURLRegex = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	jsAPIPathRegex   = regexp.MustCompile(`(?i)(/api/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]+|/v[0-9]+/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]+|/graphql(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]*)?|/rest/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]+)`)
	quotedPathRegex  = regexp.MustCompile(`["'](/[^"'?#\s]{1,180})["']`)
)

func CheckAttackSurfaceIntelligencePassive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	findings := make([]report.Finding, 0)
	body := string(ctx.BodyBytes)
	baseHost := strings.ToLower(ctx.FinalURL.Hostname())
	root := effectiveRootDomain(baseHost)
	policy := config.LoadScanPolicyFromPRS()
	maxShadow := policy.ASIMaxShadowCandidates
	if maxShadow <= 0 {
		maxShadow = 30
	}

	seenExternal := map[string]struct{}{}
	seenSubdomain := map[string]struct{}{}
	seenEndpoint := map[string]struct{}{}
	seenShadowAPI := map[string]struct{}{}
	seenBucket := map[string]struct{}{}
	seenDocs := map[string]struct{}{}
	seenWS := map[string]struct{}{}
	seenDevArtifact := map[string]struct{}{}
	absoluteMatches := absoluteURLRegex.FindAllString(body, -1)
	jsPathMatches := jsAPIPathRegex.FindAllString(body, -1)

	for _, m := range absoluteMatches {
		u, err := url.Parse(m)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == baseHost {
			continue
		}

		if root != "" && strings.HasSuffix(host, "."+root) {
			if _, ok := seenSubdomain[host]; !ok {
				seenSubdomain[host] = struct{}{}
				findings = append(findings, report.Finding{
					ID:           "ASI_SUBDOMAIN_DISCOVERED",
					Category:     string(checks.CategoryInfrastructure),
					Severity:     report.SeverityInfo,
					Confidence:   report.ConfidenceMedium,
					Title:        "Subdomain Discovered",
					Message:      "Referenced subdomain found in page content: " + host,
					Evidence:     host,
					Fix:          "Validate ownership and security posture of referenced subdomains and decommission unused ones.",
					AffectedURLs: []string{ctx.FinalURL.String()},
				})
			}
			continue
		}

		if _, ok := seenExternal[host]; !ok {
			seenExternal[host] = struct{}{}
			findings = append(findings, report.Finding{
				ID:           "ASI_EXTERNAL_ASSET_DISCOVERED",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityInfo,
				Confidence:   report.ConfidenceMedium,
				Title:        "External Asset Reference Discovered",
				Message:      "External third-party host is referenced by the page: " + host,
				Evidence:     m,
				Fix:          "Review third-party dependencies and enforce allowlisted external domains with integrity controls where possible.",
				AffectedURLs: []string{ctx.FinalURL.String()},
			})
		}
	}

	path := strings.ToLower(ctx.FinalURL.Path)
	if isExposedEndpointPath(path) {
		msg := "Potentially exposed endpoint path detected: " + ctx.FinalURL.Path
		sev := report.SeverityLow
		if strings.Contains(path, "actuator") || strings.Contains(path, "debug") || strings.Contains(path, "swagger") {
			sev = report.SeverityMedium
		}
		findings = append(findings, report.Finding{
			ID:           "ASI_EXPOSED_ENDPOINT",
			Category:     string(checks.CategoryInfrastructure),
			Severity:     sev,
			Confidence:   report.ConfidenceMedium,
			Title:        "Potentially Exposed Endpoint",
			Message:      msg,
			Evidence:     ctx.FinalURL.String(),
			Fix:          "Restrict access to operational endpoints and disable unnecessary public exposure in production.",
			AffectedURLs: []string{ctx.FinalURL.String()},
		})
	}

	for _, match := range jsPathMatches {
		if len(seenShadowAPI) >= maxShadow {
			break
		}
		candidate := normalizePathCandidate(match, policy.ASIRequireAPIToken)
		if candidate == "" {
			continue
		}
		if _, ok := seenShadowAPI[candidate]; ok {
			continue
		}
		seenShadowAPI[candidate] = struct{}{}
		findings = append(findings, report.Finding{
			ID:           "ASI_SHADOW_API_CANDIDATE",
			Category:     string(checks.CategoryAPISecurity),
			Severity:     report.SeverityLow,
			Confidence:   report.ConfidenceLow,
			Title:        "Shadow API Candidate",
			Message:      "API-like route referenced in content but not guaranteed to be in normal navigation scope: " + candidate,
			Evidence:     candidate,
			Fix:          "Inventory API routes and enforce centralized authentication, authorization, and lifecycle ownership.",
			AffectedURLs: []string{ctx.FinalURL.String()},
		})
	}

	for _, m := range absoluteMatches {
		u, err := url.Parse(m)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if !isBucketHost(host) {
			continue
		}
		bucketRef := host + u.EscapedPath()
		if _, ok := seenBucket[bucketRef]; ok {
			continue
		}
		seenBucket[bucketRef] = struct{}{}
		findings = append(findings, report.Finding{
			ID:           "ASI_PUBLIC_BUCKET_REFERENCE",
			Category:     string(checks.CategoryInfrastructure),
			Severity:     report.SeverityInfo,
			Confidence:   report.ConfidenceLow,
			Title:        "Public Bucket Reference Detected",
			Message:      "Object storage reference detected (possible public bucket/object): " + bucketRef,
			Evidence:     m,
			Fix:          "Validate bucket/object ACL and block public access unless explicitly required.",
			AffectedURLs: []string{ctx.FinalURL.String()},
		})
	}

	for _, m := range absoluteMatches {
		u, err := url.Parse(m)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if !strings.EqualFold(u.Hostname(), baseHost) {
			continue
		}
		p := strings.ToLower(u.Path)
		if !isExposedEndpointPath(p) {
			continue
		}
		key := p
		if _, ok := seenEndpoint[key]; ok {
			continue
		}
		seenEndpoint[key] = struct{}{}
		findings = append(findings, report.Finding{
			ID:           "ASI_EXPOSED_ENDPOINT_REFERENCE",
			Category:     string(checks.CategoryInfrastructure),
			Severity:     report.SeverityLow,
			Confidence:   report.ConfidenceLow,
			Title:        "Exposed Endpoint Reference",
			Message:      "Sensitive endpoint-like route referenced in page content: " + u.Path,
			Evidence:     u.String(),
			Fix:          "Ensure sensitive operational endpoints are protected and not linked from public pages.",
			AffectedURLs: []string{ctx.FinalURL.String()},
		})
	}

	for _, m := range quotedPathRegex.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		p := strings.TrimSpace(m[1])
		lp := strings.ToLower(p)
		if lp == "" {
			continue
		}
		if isLikelyAPIDocsPath(lp) {
			if _, ok := seenDocs[lp]; !ok {
				seenDocs[lp] = struct{}{}
				findings = append(findings, report.Finding{
					ID:           "ASI_API_DOCS_REFERENCE",
					Category:     string(checks.CategoryInfrastructure),
					Severity:     report.SeverityLow,
					Confidence:   report.ConfidenceMedium,
					Title:        "API Docs/Schema Reference Discovered",
					Message:      "Potential API documentation or schema endpoint referenced in content: " + p,
					Evidence:     p,
					Fix:          "Limit public access to API docs/schema endpoints in production or enforce authentication.",
					AffectedURLs: []string{ctx.FinalURL.String()},
				})
			}
		}
		if isLikelyWebSocketPath(lp) {
			if _, ok := seenWS[lp]; !ok {
				seenWS[lp] = struct{}{}
				findings = append(findings, report.Finding{
					ID:           "ASI_WEBSOCKET_ENDPOINT_REFERENCE",
					Category:     string(checks.CategoryInfrastructure),
					Severity:     report.SeverityInfo,
					Confidence:   report.ConfidenceLow,
					Title:        "WebSocket Endpoint Reference Discovered",
					Message:      "WebSocket-like endpoint path referenced in content: " + p,
					Evidence:     p,
					Fix:          "Ensure WebSocket endpoints enforce authentication and origin checks with least-privilege authorization.",
					AffectedURLs: []string{ctx.FinalURL.String()},
				})
			}
		}
		if strings.HasSuffix(lp, ".map") && !strings.HasSuffix(lp, ".css.map") {
			if _, ok := seenDevArtifact[lp]; !ok {
				seenDevArtifact[lp] = struct{}{}
				findings = append(findings, report.Finding{
					ID:           "ASI_DEV_ARTIFACT_REFERENCE",
					Category:     string(checks.CategoryInformationLeakage),
					Severity:     report.SeverityInfo,
					Confidence:   report.ConfidenceMedium,
					Title:        "Development Artifact Reference Discovered",
					Message:      "Source map or development artifact reference detected: " + p,
					Evidence:     p,
					Fix:          "Avoid exposing source maps in production or restrict access to trusted users.",
					AffectedURLs: []string{ctx.FinalURL.String()},
				})
			}
		}
	}

	return findings, nil
}

func effectiveRootDomain(host string) string {
	if host == "" {
		return ""
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return root
}

func normalizePathCandidate(v string, requireAPIToken bool) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "?"); i >= 0 {
		v = v[:i]
	}
	if len(v) > 180 {
		v = v[:180]
	}
	if !isLikelyAPIPathCandidate(strings.ToLower(v), requireAPIToken) {
		return ""
	}
	return v
}

func isLikelyAPIPathCandidate(path string, requireAPIToken bool) bool {
	if path == "" {
		return false
	}
	// Skip obvious static assets to reduce shadow-API false positives.
	staticExt := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".txt",
	}
	for _, ext := range staticExt {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	if !requireAPIToken {
		return true
	}
	// Require API-ish signal in path.
	apiTokens := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/service/", "/internal/api",
	}
	for _, t := range apiTokens {
		if strings.Contains(path, t) {
			return true
		}
	}
	return false
}

func isExposedEndpointPath(path string) bool {
	if path == "" {
		return false
	}
	patterns := []string{
		"/.git", "/.env", "/actuator", "/debug", "/swagger", "/openapi",
		"/graphql", "/graphiql", "/api-docs", "/metrics", "/health", "/status",
		"/admin", "/manage", "/internal",
	}
	for _, p := range patterns {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func isBucketHost(host string) bool {
	return strings.Contains(host, "s3.amazonaws.com") ||
		strings.Contains(host, "storage.googleapis.com") ||
		strings.Contains(host, ".blob.core.windows.net") ||
		strings.Contains(host, ".digitaloceanspaces.com")
}

func isLikelyAPIDocsPath(path string) bool {
	if path == "" {
		return false
	}
	docsTokens := []string{
		"/swagger", "/swagger-ui", "/swagger.json",
		"/openapi", "/openapi.json",
		"/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
		"/redoc", "/graphiql", "/playground",
	}
	for _, t := range docsTokens {
		if strings.Contains(path, t) {
			return true
		}
	}
	return false
}

func isLikelyWebSocketPath(path string) bool {
	if path == "" {
		return false
	}
	wsTokens := []string{"/ws", "/websocket", "/socket", "/sockjs"}
	for _, t := range wsTokens {
		if strings.Contains(path, t) {
			return true
		}
	}
	return false
}
