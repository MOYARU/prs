package info

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/config"
	"github.com/MOYARU/prs/internal/report"
)

const (
	maxActiveShadowAPIProbes = 10
	maxActiveBucketProbes    = 8
	maxActiveDocsProbes      = 8
)

func CheckAttackSurfaceIntelligenceActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	body := string(ctx.BodyBytes)
	baseHost := strings.ToLower(ctx.FinalURL.Hostname())
	findings := make([]report.Finding, 0)
	policy := config.LoadScanPolicyFromPRS()
	absoluteMatches := absoluteURLRegex.FindAllString(body, -1)
	jsPathMatches := jsAPIPathRegex.FindAllString(body, -1)

	shadowCandidates := collectShadowAPICandidates(jsPathMatches, policy.ASIRequireAPIToken)
	bucketCandidates := collectBucketCandidates(absoluteMatches)
	exposedRefCandidates := collectSameHostExposedRefs(absoluteMatches, baseHost)
	docsCandidates := collectAPIDocsCandidates(body, absoluteMatches, ctx.FinalURL, baseHost)
	maxShadow := policy.ASIMaxShadowCandidates
	if maxShadow <= 0 {
		maxShadow = maxActiveShadowAPIProbes
	}

	for i, path := range shadowCandidates {
		if i >= maxShadow {
			break
		}
		target := resolvePathAgainstFinalURL(ctx.FinalURL, path)
		if target == "" {
			continue
		}
		resp, err := doASIRequest(ctx, http.MethodGet, target)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		isLikelyAPI := strings.Contains(ct, "application/json") || strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/")
		if resp.StatusCode == http.StatusOK && isLikelyAPI {
			findings = append(findings, report.Finding{
				ID:           "ASI_SHADOW_API_VERIFIED",
				Category:     string(checks.CategoryAPISecurity),
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceMedium,
				Title:        "Shadow API Endpoint Verified",
				Message:      "A shadow API candidate responded successfully and appears accessible without explicit control checks.",
				Evidence:     target + " [" + resp.Status + "]",
				Fix:          "Inventory this API endpoint and enforce authentication/authorization, schema validation, and ownership controls.",
				AffectedURLs: []string{ctx.FinalURL.String(), target},
			})
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			findings = append(findings, report.Finding{
				ID:           "ASI_SHADOW_API_RESTRICTED",
				Category:     string(checks.CategoryAPISecurity),
				Severity:     report.SeverityInfo,
				Confidence:   report.ConfidenceHigh,
				Title:        "Shadow API Candidate Exists (Access Restricted)",
				Message:      "The candidate endpoint exists but appears access-controlled.",
				Evidence:     target + " [" + resp.Status + "]",
				Fix:          "Keep authorization in place and verify no alternate paths expose equivalent data.",
				AffectedURLs: []string{ctx.FinalURL.String(), target},
			})
		} else if resp.StatusCode == http.StatusOK && len(respBody) > 0 && strings.Contains(strings.ToLower(string(respBody)), "swagger") {
			findings = append(findings, report.Finding{
				ID:           "ASI_EXPOSED_ENDPOINT_VERIFIED",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceMedium,
				Title:        "Exposed Endpoint Verified",
				Message:      "A sensitive endpoint-like route appears publicly reachable.",
				Evidence:     target + " [" + resp.Status + "]",
				Fix:          "Restrict endpoint exposure and require proper authentication in production.",
				AffectedURLs: []string{ctx.FinalURL.String(), target},
			})
		}
	}

	for i, ref := range docsCandidates {
		if i >= maxActiveDocsProbes {
			break
		}
		resp, err := doASIRequest(ctx, http.MethodGet, ref)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}
		bodyLower := strings.ToLower(string(bodyBytes))
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct, "application/json") && (strings.Contains(bodyLower, "\"openapi\"") || strings.Contains(bodyLower, "\"swagger\"") || strings.Contains(bodyLower, "\"paths\"")) {
			findings = append(findings, report.Finding{
				ID:           "ASI_API_DOCS_EXPOSED",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceHigh,
				Title:        "API Documentation/Schema Exposed",
				Message:      "API documentation or schema endpoint appears publicly reachable.",
				Evidence:     ref + " [" + resp.Status + "]",
				Fix:          "Restrict API docs access in production or require authentication and network controls.",
				AffectedURLs: []string{ctx.FinalURL.String(), ref},
			})
			continue
		}
		if strings.Contains(bodyLower, "swagger ui") || strings.Contains(bodyLower, "openapi") || strings.Contains(bodyLower, "redoc") {
			findings = append(findings, report.Finding{
				ID:           "ASI_API_DOCS_EXPOSED",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceMedium,
				Title:        "API Documentation Interface Exposed",
				Message:      "Interactive API documentation page appears publicly reachable.",
				Evidence:     ref + " [" + resp.Status + "]",
				Fix:          "Restrict documentation UI in production and expose only through authenticated/internal channels.",
				AffectedURLs: []string{ctx.FinalURL.String(), ref},
			})
		}
	}

	for i, ref := range exposedRefCandidates {
		if i >= maxActiveShadowAPIProbes {
			break
		}
		resp, err := doASIRequest(ctx, http.MethodGet, ref)
		if err != nil {
			continue
		}
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			findings = append(findings, report.Finding{
				ID:           "ASI_EXPOSED_ENDPOINT_VERIFIED",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceMedium,
				Title:        "Exposed Endpoint Verified",
				Message:      "A sensitive endpoint reference was confirmed accessible.",
				Evidence:     ref + " [" + resp.Status + "]",
				Fix:          "Protect operational endpoints with strict access controls and network policy.",
				AffectedURLs: []string{ctx.FinalURL.String(), ref},
			})
		}
	}

	for i, bucketURL := range bucketCandidates {
		if i >= maxActiveBucketProbes {
			break
		}
		resp, err := doASIRequest(ctx, http.MethodHead, bucketURL)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			findings = append(findings, report.Finding{
				ID:           "ASI_PUBLIC_BUCKET_ACCESSIBLE",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceMedium,
				Title:        "Public Bucket/Object Accessibility Signal",
				Message:      "Referenced object storage URL is directly reachable, indicating potential public exposure.",
				Evidence:     bucketURL + " [" + resp.Status + "]",
				Fix:          "Review bucket/object ACL and block unauthenticated access unless business-justified.",
				AffectedURLs: []string{ctx.FinalURL.String(), bucketURL},
			})
		case http.StatusForbidden, http.StatusUnauthorized:
			findings = append(findings, report.Finding{
				ID:           "ASI_PUBLIC_BUCKET_RESTRICTED",
				Category:     string(checks.CategoryInfrastructure),
				Severity:     report.SeverityInfo,
				Confidence:   report.ConfidenceHigh,
				Title:        "Bucket Reference Exists (Access Restricted)",
				Message:      "Bucket/object reference exists but access appears restricted.",
				Evidence:     bucketURL + " [" + resp.Status + "]",
				Fix:          "Maintain restricted access and periodically validate public-access settings.",
				AffectedURLs: []string{ctx.FinalURL.String(), bucketURL},
			})
		}
	}

	return dedupeASIFindings(findings), nil
}

func collectShadowAPICandidates(matches []string, requireAPIToken bool) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, match := range matches {
		candidate := normalizePathCandidate(match, requireAPIToken)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func collectBucketCandidates(matches []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, raw := range matches {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if !isBucketHost(strings.ToLower(u.Hostname())) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func collectSameHostExposedRefs(matches []string, baseHost string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, raw := range matches {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if !strings.EqualFold(u.Hostname(), baseHost) {
			continue
		}
		if !isExposedEndpointPath(strings.ToLower(u.Path)) {
			continue
		}
		target := u.String()
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func collectAPIDocsCandidates(body string, absoluteMatches []string, base *url.URL, baseHost string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)

	appendPath := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || base == nil {
			return
		}
		u := resolvePathAgainstFinalURL(base, raw)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	for _, m := range quotedPathRegex.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		p := strings.ToLower(strings.TrimSpace(m[1]))
		if !isLikelyAPIDocsPath(p) {
			continue
		}
		appendPath(m[1])
	}

	for _, m := range absoluteMatches {
		u, err := url.Parse(m)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if !strings.EqualFold(u.Hostname(), baseHost) {
			continue
		}
		if !isLikelyAPIDocsPath(strings.ToLower(u.Path)) {
			continue
		}
		appendPath(u.Path)
	}

	common := []string{
		"/swagger", "/swagger-ui", "/swagger-ui/index.html", "/swagger.json",
		"/openapi.json", "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
		"/redoc", "/graphiql",
	}
	for _, p := range common {
		appendPath(p)
	}
	return out
}

func resolvePathAgainstFinalURL(base *url.URL, path string) string {
	if base == nil || path == "" {
		return ""
	}
	ref, err := url.Parse(path)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func doASIRequest(ctx *ctxpkg.Context, method, target string) (*http.Response, error) {
	req, err := ctxpkg.NewRequest(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PRS-ASI/1.0")
	return ctx.HTTPClient.Do(req)
}

func dedupeASIFindings(findings []report.Finding) []report.Finding {
	type k struct {
		ID       string
		Evidence string
	}
	seen := map[k]struct{}{}
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		key := k{ID: f.ID, Evidence: f.Evidence}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
