package headers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

const hstsMaxAgeBaseline = 31536000

func CheckSecurityHeaders(ctx *ctxpkg.Context) ([]report.Finding, error) {
	if ctx.Response == nil {
		return nil, nil
	}

	headers := ctx.Response.Header
	var findings []report.Finding

	// Check for missing headers and aggregate them
	headersToCheck := []struct {
		Name     string
		Severity report.Severity
	}{
		{"Content-Security-Policy", report.SeverityMedium},
		{"X-Frame-Options", report.SeverityLow},
		{"X-Content-Type-Options", report.SeverityLow},
		{"Referrer-Policy", report.SeverityLow},
		{"Permissions-Policy", report.SeverityLow},
		{"Cross-Origin-Opener-Policy", report.SeverityLow},
		{"Cross-Origin-Embedder-Policy", report.SeverityLow},
		{"Cross-Origin-Resource-Policy", report.SeverityLow},
	}

	var missing []string
	maxSeverity := report.SeverityLow

	for _, h := range headersToCheck {
		if headers.Get(h.Name) == "" {
			missing = append(missing, h.Name)
			if h.Severity == report.SeverityMedium {
				maxSeverity = report.SeverityMedium
			}
		}
	}

	if len(missing) > 0 {
		msg := msges.GetMessage("MISSING_SECURITY_HEADERS")
		findings = append(findings, report.Finding{
			ID:       "MISSING_SECURITY_HEADERS",
			Category: string(checks.CategorySecurityHeaders),
			Severity: maxSeverity,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(missing, ", ")),
			Fix:      msg.Fix,
		})
	}

	findings = append(findings, checkHSTS(ctx, headers)...)
	findings = append(findings, checkInfoHeaders(headers)...)

	return findings, nil
}

func checkHSTS(ctx *ctxpkg.Context, headers http.Header) []report.Finding {
	if ctx.FinalURL == nil || ctx.FinalURL.Scheme != "https" {
		return nil
	}

	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		msg := msges.GetMessage("HSTS_MISSING")
		return []report.Finding{
			{
				ID:       "HSTS_MISSING",
				Category: string(checks.CategorySecurityHeaders),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			},
		}
	}

	maxAge := parseHSTSMaxAge(hsts)
	if maxAge > 0 && maxAge < hstsMaxAgeBaseline {
		msg := msges.GetMessage("HSTS_MAXAGE_LOW")
		return []report.Finding{
			{
				ID:       "HSTS_MAXAGE_LOW",
				Category: string(checks.CategorySecurityHeaders),
				Severity: report.SeverityMedium,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			},
		}
	}

	return nil
}

func parseHSTSMaxAge(hsts string) int {
	parts := strings.Split(hsts, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			value := strings.TrimSpace(kv[1])
			parsed, err := strconv.Atoi(value)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func checkCookieFlags(resp *http.Response) []report.Finding {
	if resp == nil {
		return nil
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return nil
	}

	var insecureCookies []string
	var httpOnlyMissing []string
	var sameSiteMissing []string
	var sameSiteNoneInsecure []string

	for _, cookie := range cookies {
		if !cookie.Secure {
			insecureCookies = append(insecureCookies, cookie.Name)
		}
		if !cookie.HttpOnly {
			httpOnlyMissing = append(httpOnlyMissing, cookie.Name)
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			sameSiteMissing = append(sameSiteMissing, cookie.Name)
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			sameSiteNoneInsecure = append(sameSiteNoneInsecure, cookie.Name)
		}
	}

	var findings []report.Finding

	if len(insecureCookies) > 0 {
		msg := msges.GetMessage("COOKIE_SECURE_MISSING")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SECURE_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(insecureCookies, ", ")),
			Fix:      msg.Fix,
		})
	}

	if len(httpOnlyMissing) > 0 {
		msg := msges.GetMessage("COOKIE_HTTPONLY_MISSING")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_HTTPONLY_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(httpOnlyMissing, ", ")),
			Fix:      msg.Fix,
		})
	}

	if len(sameSiteMissing) > 0 {
		msg := msges.GetMessage("COOKIE_SAMESITE_MISSING")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SAMESITE_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityLow,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(sameSiteMissing, ", ")),
			Fix:      msg.Fix,
		})
	}

	if len(sameSiteNoneInsecure) > 0 {
		msg := msges.GetMessage("COOKIE_SAMESITE_NONE_INSECURE")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SAMESITE_NONE_INSECURE",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(sameSiteNoneInsecure, ", ")),
			Fix:      msg.Fix,
		})
	}

	return findings
}

func checkInfoHeaders(headers http.Header) []report.Finding {
	var findings []report.Finding

	if server := headers.Get("Server"); server != "" {
		msg := msges.GetMessage("SERVER_HEADER_EXPOSED")
		findings = append(findings, report.Finding{
			ID:       "SERVER_HEADER_EXPOSED",
			Category: string(checks.CategoryInfrastructure),
			Severity: report.SeverityInfo,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		msg := msges.GetMessage("X_POWERED_BY_EXPOSED")
		findings = append(findings, report.Finding{
			ID:       "X_POWERED_BY_EXPOSED",
			Category: string(checks.CategoryInfrastructure),
			Severity: report.SeverityInfo,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	return findings
}
