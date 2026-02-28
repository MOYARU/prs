package tokenreuse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

// CheckJWTAlgNoneActive verifies whether JWT tokens are accepted with alg=none.
func CheckJWTAlgNoneActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.HTTPClient == nil || ctx.FinalURL == nil {
		return findings, nil
	}

	candidates := extractTokenCandidates(ctx)
	if len(candidates) == 0 {
		return findings, nil
	}

	controlToken := "prs-invalid-token-none-check"
	controlProbe, err := runAuthProbe(ctx, controlToken)
	if err != nil {
		return findings, nil
	}

	for _, c := range candidates {
		if strings.Count(c.Value, ".") != 2 {
			continue
		}
		noneToken, ok := buildAlgNoneToken(c.Value)
		if !ok {
			continue
		}

		origProbe, err := runAuthProbe(ctx, c.Value)
		if err != nil || !isAuthSuccessProbe(origProbe) {
			continue
		}
		noneProbe, err := runAuthProbe(ctx, noneToken)
		if err != nil {
			continue
		}
		if !isAuthSuccessProbe(noneProbe) {
			continue
		}

		bodyDiff := origProbe.BodyLen - noneProbe.BodyLen
		if bodyDiff < 0 {
			bodyDiff = -bodyDiff
		}
		if noneProbe.StatusCode == origProbe.StatusCode && bodyDiff < 200 {
			findings = append(findings, report.Finding{
				ID:                         "JWT_ALG_NONE_ACCEPTED",
				Category:                   string(checks.CategoryAPISecurity),
				Severity:                   report.SeverityHigh,
				Confidence:                 report.ConfidenceMedium,
				Validation:                 report.ValidationProbable,
				Title:                      "JWT alg=none Acceptance Signal",
				Message:                    "A JWT candidate appears accepted even when converted to alg=none. This may indicate signature verification weakness.",
				Evidence:                   fmt.Sprintf("Source=%s, ControlStatus=%d, OrigStatus=%d, NoneStatus=%d, BodyDiff=%d", c.Source, controlProbe.StatusCode, origProbe.StatusCode, noneProbe.StatusCode, bodyDiff),
				Fix:                        "Reject unsecured JWT algorithms, enforce strict signature verification, and pin accepted algorithms server-side.",
				IsPotentiallyFalsePositive: true,
			})
			break
		}

		// Fallback channels: query/cookie replay if key candidate exists.
		if c.Key != "" {
			qOrig, qErr1 := runQueryProbe(ctx, c.Key, c.Value)
			qNone, qErr2 := runQueryProbe(ctx, c.Key, noneToken)
			if qErr1 == nil && qErr2 == nil && isAuthSuccessProbe(qOrig) && isAuthSuccessProbe(qNone) &&
				qOrig.StatusCode == qNone.StatusCode {
				findings = append(findings, report.Finding{
					ID:                         "JWT_ALG_NONE_ACCEPTED",
					Category:                   string(checks.CategoryAPISecurity),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceLow,
					Validation:                 report.ValidationProbable,
					Title:                      "JWT alg=none Acceptance Signal (Query)",
					Message:                    "JWT candidate appears accepted via query parameter even when converted to alg=none.",
					Evidence:                   fmt.Sprintf("Key=%s, OrigStatus=%d, NoneStatus=%d", c.Key, qOrig.StatusCode, qNone.StatusCode),
					Fix:                        "Reject unsecured JWT algorithms and avoid accepting auth tokens via query parameters.",
					IsPotentiallyFalsePositive: true,
				})
				break
			}
			cOrig, cErr1 := runCookieProbe(ctx, c.Key, c.Value)
			cNone, cErr2 := runCookieProbe(ctx, c.Key, noneToken)
			if cErr1 == nil && cErr2 == nil && isAuthSuccessProbe(cOrig) && isAuthSuccessProbe(cNone) &&
				cOrig.StatusCode == cNone.StatusCode {
				findings = append(findings, report.Finding{
					ID:                         "JWT_ALG_NONE_ACCEPTED",
					Category:                   string(checks.CategoryAPISecurity),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceLow,
					Validation:                 report.ValidationProbable,
					Title:                      "JWT alg=none Acceptance Signal (Cookie)",
					Message:                    "JWT candidate appears accepted via cookie even when converted to alg=none.",
					Evidence:                   fmt.Sprintf("Key=%s, OrigStatus=%d, NoneStatus=%d", c.Key, cOrig.StatusCode, cNone.StatusCode),
					Fix:                        "Reject unsecured JWT algorithms and enforce strict token verification on cookie-based auth.",
					IsPotentiallyFalsePositive: true,
				})
				break
			}
		}
	}

	return findings, nil
}

func buildAlgNoneToken(jwt string) (string, bool) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", false
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", false
	}
	header["alg"] = "none"
	updatedHeader, err := json.Marshal(header)
	if err != nil {
		return "", false
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(updatedHeader)
	return encodedHeader + "." + parts[1] + ".", true
}

func isAuthSuccessProbe(p probeResult) bool {
	if p.StatusCode >= 200 && p.StatusCode < 300 {
		return true
	}
	if p.StatusCode >= 300 && p.StatusCode < 400 && !isRedirectToLogin(p.Location) {
		return true
	}
	return p.HasAuthKeywords
}
