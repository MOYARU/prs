package tokenreuse

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

const (
	maxTokenCandidates = 6
	maxProbeBodyBytes  = 256 * 1024
)

var (
	tokenKVPattern = regexp.MustCompile(`(?i)(token|access[_-]?token|api[_-]?key|auth(?:orization)?|session(?:id)?)\s*[:=]\s*["']?([A-Za-z0-9._\-]{16,})["']?`)
)

type tokenCandidate struct {
	Source string
	Key    string
	Value  string
}

type probeResult struct {
	StatusCode      int
	BodyLen         int
	HasAuthKeywords bool
	Location        string
}

func CheckTokenReuse(ctx *ctxpkg.Context) ([]report.Finding, error) {
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.HTTPClient == nil || ctx.FinalURL == nil {
		return nil, nil
	}

	candidates := extractTokenCandidates(ctx)
	if len(candidates) == 0 {
		return nil, nil
	}

	controlToken := "prs-invalid-token-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	controlProbe, err := runAuthProbe(ctx, controlToken)
	if err != nil {
		return nil, nil
	}

	findings := make([]report.Finding, 0, 2)
	for _, candidate := range candidates {
		authProbe, err := runAuthProbe(ctx, candidate.Value)
		if err == nil {
			if finding, ok := buildFindingFromDelta(candidate, "Authorization: Bearer", controlProbe, authProbe); ok {
				findings = append(findings, finding)
				if len(findings) >= 2 {
					return findings, nil
				}
			}
		}

		if candidate.Key != "" {
			queryProbe, err := runQueryProbe(ctx, candidate.Key, candidate.Value)
			if err == nil {
				if finding, ok := buildFindingFromDelta(candidate, "Query Parameter", controlProbe, queryProbe); ok {
					findings = append(findings, finding)
					if len(findings) >= 2 {
						return findings, nil
					}
				}
			}

			cookieProbe, err := runCookieProbe(ctx, candidate.Key, candidate.Value)
			if err == nil {
				if finding, ok := buildFindingFromDelta(candidate, "Cookie", controlProbe, cookieProbe); ok {
					findings = append(findings, finding)
					if len(findings) >= 2 {
						return findings, nil
					}
				}
			}
		}
	}

	return findings, nil
}

func extractTokenCandidates(ctx *ctxpkg.Context) []tokenCandidate {
	candidates := make([]tokenCandidate, 0, maxTokenCandidates)
	seenValues := map[string]bool{}

	parsedURL, err := url.Parse(ctx.FinalURL.String())
	if err == nil {
		for key, values := range parsedURL.Query() {
			if !looksLikeTokenKey(key) {
				continue
			}
			for _, v := range values {
				v = strings.TrimSpace(v)
				if !looksLikeTokenValue(v) || seenValues[v] {
					continue
				}
				seenValues[v] = true
				candidates = append(candidates, tokenCandidate{
					Source: "URL Query",
					Key:    key,
					Value:  v,
				})
				if len(candidates) >= maxTokenCandidates {
					return candidates
				}
			}
		}
	}

	body := string(ctx.BodyBytes)
	for _, match := range tokenKVPattern.FindAllStringSubmatch(body, maxTokenCandidates*2) {
		if len(match) < 3 {
			continue
		}
		key := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		if !looksLikeTokenValue(value) || seenValues[value] {
			continue
		}
		seenValues[value] = true
		candidates = append(candidates, tokenCandidate{
			Source: "Response Body",
			Key:    key,
			Value:  value,
		})
		if len(candidates) >= maxTokenCandidates {
			return candidates
		}
	}

	return candidates
}

func looksLikeTokenKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(k, "token") ||
		strings.Contains(k, "api_key") ||
		strings.Contains(k, "apikey") ||
		strings.Contains(k, "auth") ||
		strings.Contains(k, "session")
}

func looksLikeTokenValue(v string) bool {
	if len(v) < 16 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	// UUID-like token
	if len(v) == 36 && strings.Count(v, "-") == 4 {
		return true
	}
	// JWT-like token
	if strings.Count(v, ".") == 2 && len(v) >= 32 {
		return true
	}
	// Generic long token
	return len(v) >= 24
}

func runAuthProbe(ctx *ctxpkg.Context, token string) (probeResult, error) {
	req, err := ctxpkg.NewRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
	if err != nil {
		return probeResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return executeProbe(ctx, req)
}

func runQueryProbe(ctx *ctxpkg.Context, key, token string) (probeResult, error) {
	parsed, err := url.Parse(ctx.FinalURL.String())
	if err != nil {
		return probeResult{}, err
	}
	q := parsed.Query()
	q.Set(key, token)
	parsed.RawQuery = q.Encode()

	req, err := ctxpkg.NewRequest(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return probeResult{}, err
	}
	return executeProbe(ctx, req)
}

func runCookieProbe(ctx *ctxpkg.Context, key, token string) (probeResult, error) {
	req, err := ctxpkg.NewRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
	if err != nil {
		return probeResult{}, err
	}

	cookieName := normalizeCookieKey(key)
	if cookieName == "" {
		cookieName = "session"
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	return executeProbe(ctx, req)
}

func normalizeCookieKey(key string) string {
	k := strings.TrimSpace(strings.ToLower(key))
	switch k {
	case "access_token", "accesstoken":
		return "access_token"
	case "sessionid", "session_id":
		return "sessionid"
	case "auth", "authorization":
		return "auth"
	case "token":
		return "token"
	default:
		if k == "" {
			return ""
		}
		return k
	}
}

func executeProbe(ctx *ctxpkg.Context, req *http.Request) (probeResult, error) {
	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	bodyLower := strings.ToLower(string(bodyBytes))

	return probeResult{
		StatusCode:      resp.StatusCode,
		BodyLen:         len(bodyBytes),
		HasAuthKeywords: containsAny(bodyLower, "logout", "sign out", "dashboard", "profile", "account", "admin"),
		Location:        strings.ToLower(resp.Header.Get("Location")),
	}, nil
}

func buildFindingFromDelta(candidate tokenCandidate, probeType string, control, candidateProbe probeResult) (report.Finding, bool) {
	score := 0
	if (control.StatusCode == http.StatusUnauthorized || control.StatusCode == http.StatusForbidden) &&
		candidateProbe.StatusCode >= 200 && candidateProbe.StatusCode < 300 {
		score += 4
	}
	if isRedirectToLogin(control.Location) &&
		candidateProbe.StatusCode >= 200 && candidateProbe.StatusCode < 300 {
		score += 3
	}
	if candidateProbe.HasAuthKeywords && !control.HasAuthKeywords {
		score += 2
	}
	if control.StatusCode >= 400 && candidateProbe.StatusCode >= 200 && candidateProbe.StatusCode < 300 {
		score += 2
	}
	if candidateProbe.BodyLen > control.BodyLen+300 {
		score++
	}

	if score < 4 {
		return report.Finding{}, false
	}

	severity := report.SeverityMedium
	confidence := report.ConfidenceMedium
	if score >= 6 {
		severity = report.SeverityHigh
		confidence = report.ConfidenceHigh
	}

	masked := maskSecret(candidate.Value)
	return report.Finding{
		ID:         "TOKEN_REUSE_POSSIBLE",
		Category:   string(checks.CategoryAPISecurity),
		Severity:   severity,
		Confidence: confidence,
		Title:      "Leaked Token Reuse Appears Valid",
		Message: fmt.Sprintf(
			"Token-like value from %s appears accepted when replayed (%s). This may indicate token leakage leading to unauthorized access.",
			candidate.Source,
			probeType,
		),
		Evidence: fmt.Sprintf(
			"Token=%s, ControlStatus=%d, CandidateStatus=%d, ControlBody=%dB, CandidateBody=%dB",
			masked,
			control.StatusCode,
			candidateProbe.StatusCode,
			control.BodyLen,
			candidateProbe.BodyLen,
		),
		Fix:                        "Do not expose tokens client-side. Rotate leaked tokens, narrow token scope/audience, enforce short expiry, and require server-side authorization checks per request.",
		IsPotentiallyFalsePositive: true,
	}, true
}

func isRedirectToLogin(location string) bool {
	if location == "" {
		return false
	}
	return strings.Contains(location, "login") ||
		strings.Contains(location, "signin") ||
		strings.Contains(location, "auth")
}

func containsAny(s string, keywords ...string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
