package authsession

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckAuthSessionHardening(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	loginPageURL := findLoginPage(ctx.InitialURL.String(), ctx.HTTPClient)
	if loginPageURL != "" {
		findings = append(findings, checkLoginPageHTTPS(ctx, loginPageURL)...)
	}

	findings = append(findings, checkCookieAttributes(ctx.Response)...)

	return findings, nil
}

func CheckSessionManagement(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}
	msg := msges.GetMessage("SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED")
	findings = append(findings, report.Finding{
		ID:                         "SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED",
		Category:                   string(checks.CategoryAuthSession),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      msg.Title,
		Message:                    msg.Message,
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
	})

	return findings, nil
}

func findLoginPage(targetURL string, client *http.Client) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	var foundURL string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	// Common login paths
	paths := []string{"/login", "/signin", "/account/login", "/user/login", "/admin/login"}
	for _, path := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			mu.Lock()
			if foundURL != "" {
				mu.Unlock()
				return
			}
			mu.Unlock()

			sem <- struct{}{}
			defer func() { <-sem }()

			testURL := u.Scheme + "://" + u.Host + path
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
				// Check body for login keywords to reduce false positives
				bodyBytes, _ := engine.DecodeResponseBody(resp)
				resp.Body.Close()
				bodyString := strings.ToLower(string(bodyBytes))
				if strings.Contains(bodyString, "password") || strings.Contains(bodyString, "login") || strings.Contains(bodyString, "signin") {
					mu.Lock()
					if foundURL == "" {
						foundURL = testURL
					}
					mu.Unlock()
				}
			} else if resp != nil {
				resp.Body.Close()
			}
		}(path)
	}
	wg.Wait()
	return foundURL
}

func checkLoginPageHTTPS(ctx *ctxpkg.Context, loginPageURL string) []report.Finding {
	var findings []report.Finding
	u, err := url.Parse(loginPageURL)
	if err != nil {
		return findings
	}

	if u.Scheme != "https" {
		msg := msges.GetMessage("LOGIN_PAGE_HTTPS_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "LOGIN_PAGE_HTTPS_MISSING",
			Category:                   string(checks.CategoryAuthSession),
			Severity:                   report.SeverityHigh,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, loginPageURL),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}
	return findings
}

func checkCookieAttributes(resp *http.Response) []report.Finding {
	if resp == nil {
		return nil
	}

	var findings []report.Finding
	cookies := resp.Cookies()

	for _, cookie := range cookies {
		isPotentiallySessionRelated := strings.Contains(strings.ToLower(cookie.Name), "session") ||
			strings.Contains(strings.ToLower(cookie.Name), "jsessionid") ||
			strings.Contains(strings.ToLower(cookie.Name), "phpsessid") ||
			strings.Contains(strings.ToLower(cookie.Name), "aspsessionid") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			strings.Contains(strings.ToLower(cookie.Name), "id") ||
			strings.Contains(strings.ToLower(cookie.Name), "_session")

		// Secure Flag
		if !cookie.Secure && strings.HasPrefix(strings.ToLower(resp.Request.URL.Scheme), "https") {
			msg := msges.GetMessage("COOKIE_SECURE_FLAG_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "COOKIE_SECURE_FLAG_MISSING",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookie.Name),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}

		// HttpOnly Flag
		if !cookie.HttpOnly {
			msg := msges.GetMessage("COOKIE_HTTPONLY_FLAG_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "COOKIE_HTTPONLY_FLAG_MISSING",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookie.Name),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}

		// Session Cookie Expiration
		if isPotentiallySessionRelated && cookie.Expires.IsZero() && cookie.MaxAge <= 0 {
			msg := msges.GetMessage("SESSION_COOKIE_NO_EXPIRATION")
			findings = append(findings, report.Finding{
				ID:                         "SESSION_COOKIE_NO_EXPIRATION",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookie.Name),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	for _, setCookieHeader := range resp.Header["Set-Cookie"] {
		if strings.Contains(setCookieHeader, "SameSite=None") && !strings.Contains(setCookieHeader, "Secure") {
			cookieName := "Unknown"
			parts := strings.Split(setCookieHeader, ";")
			if len(parts) > 0 {
				kv := strings.SplitN(parts[0], "=", 2)
				if len(kv) > 0 {
					cookieName = strings.TrimSpace(kv[0])
				}
			}
			msg := msges.GetMessage("SAMESITE_NONE_SECURE_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "SAMESITE_NONE_SECURE_MISSING",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookieName),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}
	return findings
}
