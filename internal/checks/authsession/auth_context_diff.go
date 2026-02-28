package authsession

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

func CheckAuthContextDiff(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil || ctx.Response == nil {
		return findings, nil
	}

	cookies := ctx.Response.Cookies()
	if len(cookies) == 0 {
		return findings, nil
	}

	probeURLs := buildAuthProbeURLs(ctx.FinalURL)
	bestScore := 0
	bestEvidence := ""
	for _, probeURL := range probeURLs {
		noCookie, err := runContextProbe(ctx, probeURL, nil, nil)
		if err != nil {
			continue
		}
		withCookie, err := runContextProbe(ctx, probeURL, cookies, nil)
		if err != nil {
			continue
		}
		invalidToken := "prs-invalid-" + strings.Repeat("x", 12)
		invalidAuth, err := runContextProbe(ctx, probeURL, cookies, map[string]string{"Authorization": "Bearer " + invalidToken})
		if err != nil {
			continue
		}

		score := 0
		if (noCookie.StatusCode == http.StatusUnauthorized || noCookie.StatusCode == http.StatusForbidden) &&
			withCookie.StatusCode >= 200 && withCookie.StatusCode < 300 {
			score += 3
		}
		if withCookie.HasAuthKeywords && !noCookie.HasAuthKeywords {
			score += 2
		}
		if withCookie.BodyLen > noCookie.BodyLen+220 {
			score++
		}
		if invalidAuth.StatusCode == withCookie.StatusCode && invalidAuth.HasAuthKeywords == withCookie.HasAuthKeywords {
			score++
		}
		// Strong hint for authorization inconsistency:
		// anonymous is accepted similarly to authenticated.
		if noCookie.StatusCode == withCookie.StatusCode && noCookie.BodyLen > 0 && withCookie.BodyLen > 0 {
			delta := noCookie.BodyLen - withCookie.BodyLen
			if delta < 0 {
				delta = -delta
			}
			if delta < 80 {
				score += 2
			}
		}

		if score > bestScore {
			bestScore = score
			bestEvidence = fmt.Sprintf(
				"url=%s, noCookie(status=%d,len=%d,auth=%t), withCookie(status=%d,len=%d,auth=%t), invalidAuth(status=%d,len=%d,auth=%t)",
				probeURL,
				noCookie.StatusCode, noCookie.BodyLen, noCookie.HasAuthKeywords,
				withCookie.StatusCode, withCookie.BodyLen, withCookie.HasAuthKeywords,
				invalidAuth.StatusCode, invalidAuth.BodyLen, invalidAuth.HasAuthKeywords,
			)
		}
	}

	if bestScore < 4 {
		return findings, nil
	}

	severity := report.SeverityLow
	confidence := report.ConfidenceLow
	if bestScore >= 6 {
		severity = report.SeverityMedium
		confidence = report.ConfidenceMedium
	}

	findings = append(findings, report.Finding{
		ID:                         "AUTH_CONTEXT_DIFFERENCE",
		Category:                   string(checks.CategoryAuthSession),
		Severity:                   severity,
		Confidence:                 confidence,
		Title:                      "Authentication Context Difference Detected",
		Message:                    "Response behavior changes significantly between anonymous and authenticated contexts.",
		Evidence:                   bestEvidence,
		Fix:                        "Enforce consistent authorization checks for every protected resource and reject invalid/expired credentials deterministically.",
		IsPotentiallyFalsePositive: true,
	})

	return findings, nil
}

type contextProbe struct {
	StatusCode      int
	BodyLen         int
	HasAuthKeywords bool
}

func runContextProbe(ctx *ctxpkg.Context, targetURL string, cookies []*http.Cookie, headers map[string]string) (contextProbe, error) {
	req, err := ctxpkg.NewRequest(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return contextProbe{}, err
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return contextProbe{}, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := engine.DecodeResponseBody(resp)
	l := strings.ToLower(string(bodyBytes))
	return contextProbe{
		StatusCode:      resp.StatusCode,
		BodyLen:         len(bodyBytes),
		HasAuthKeywords: strings.Contains(l, "logout") || strings.Contains(l, "dashboard") || strings.Contains(l, "my account"),
	}, nil
}

func buildAuthProbeURLs(base *url.URL) []string {
	if base == nil {
		return nil
	}
	candidates := []string{base.String()}
	common := []string{"/admin", "/dashboard", "/account", "/profile", "/me"}
	for _, p := range common {
		u := *base
		u.Path = p
		u.RawQuery = ""
		candidates = append(candidates, u.String())
	}

	uniq := make(map[string]struct{})
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, ok := uniq[c]; ok {
			continue
		}
		uniq[c] = struct{}{}
		out = append(out, c)
	}

	// Keep probe set small for scan speed; prioritize likely protected paths.
	sort.SliceStable(out, func(i, j int) bool {
		return authPathScore(out[i]) > authPathScore(out[j])
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func authPathScore(raw string) int {
	l := strings.ToLower(raw)
	score := 0
	if strings.Contains(l, "/admin") {
		score += 5
	}
	if strings.Contains(l, "/dashboard") || strings.Contains(l, "/account") || strings.Contains(l, "/profile") || strings.Contains(l, "/me") {
		score += 4
	}
	if strings.Contains(l, "auth") || strings.Contains(l, "user") {
		score += 2
	}
	return score
}
