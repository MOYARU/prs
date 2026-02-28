package scan

import (
	"strings"

	"github.com/MOYARU/prs/internal/report"
)

func buildChainedFindings(findings []report.Finding) []report.Finding {
	byID := make(map[string]bool, len(findings))
	for _, f := range findings {
		byID[f.ID] = true
	}

	var chained []report.Finding

	// Chain 1: reflection/xss context + weak client controls.
	hasReflection := byID["INPUT_REFLECTION_DETECTED"] || byID["REFLECTED_XSS"] || byID["REFLECTED_XSS_PASSIVE_INDICATOR"]
	hasWeakClientControls := byID["MISSING_SECURITY_HEADERS"] || byID["INLINE_SCRIPT_DETECTED"]
	hasSessionRisk := byID["COOKIE_HTTPONLY_FLAG_MISSING"] || byID["SESSION_COOKIE_NO_EXPIRATION"]
	if hasReflection && hasWeakClientControls && hasSessionRisk {
		chained = append(chained, report.Finding{
			ID:                         "CHAIN_XSS_TO_SESSION_RISK",
			Category:                   "CAT_CHAIN",
			Severity:                   report.SeverityHigh,
			Confidence:                 report.ConfidenceMedium,
			Title:                      "Chained Risk: XSS to Session Compromise",
			Message:                    "Combined findings indicate a realistic chain from script injection/reflection to session abuse.",
			Evidence:                   "Signals: reflection/XSS + weak client controls + weak session cookie posture",
			Fix:                        "Prioritize reflected XSS remediation, enforce strict CSP, and harden session cookies (HttpOnly/Secure/SameSite).",
			IsPotentiallyFalsePositive: true,
		})
	}

	// Chain 2: leaked token + access control weakness.
	if byID["TOKEN_REUSE_POSSIBLE"] && (byID["IDOR_POSSIBLE"] || byID["IDOR_ACTIVE"]) {
		chained = append(chained, report.Finding{
			ID:                         "CHAIN_TOKEN_TO_IDOR_RISK",
			Category:                   "CAT_CHAIN",
			Severity:                   report.SeverityHigh,
			Confidence:                 report.ConfidenceMedium,
			Title:                      "Chained Risk: Token Reuse with Access Control Weakness",
			Message:                    "Token reuse signal combined with IDOR indicators suggests broader account/resource takeover risk.",
			Evidence:                   "Signals: TOKEN_REUSE_POSSIBLE + IDOR indicators",
			Fix:                        "Rotate leaked tokens, enforce resource-level authorization, and bind token scope to user/resource context.",
			IsPotentiallyFalsePositive: true,
		})
	}

	// Keep chain findings stable and deduplicated by ID/message at caller.
	for i := range chained {
		chained[i].Message = strings.TrimSpace(chained[i].Message)
	}
	return chained
}
