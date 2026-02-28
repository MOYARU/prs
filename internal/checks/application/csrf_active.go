package application

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/crawler"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

// CheckCSRFTokenReplayActive performs a low-impact active signal check for CSRF token replay acceptance.
func CheckCSRFTokenReplayActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.Response == nil || ctx.FinalURL == nil {
		return findings, nil
	}
	if !strings.Contains(strings.ToLower(ctx.Response.Header.Get("Content-Type")), "text/html") || len(ctx.BodyBytes) == 0 {
		return findings, nil
	}

	doc, err := html.Parse(bytes.NewReader(ctx.BodyBytes))
	if err != nil {
		return findings, nil
	}
	forms := crawler.ExtractForms(doc)
	for _, form := range forms {
		if strings.ToUpper(form.Method) != "POST" || len(form.Inputs) == 0 {
			continue
		}

		tokenName, tokenValue := detectCSRFTokenField(form.Inputs)
		if tokenName == "" || tokenValue == "" {
			continue
		}

		targetURL := ctx.FinalURL.String()
		if form.ActionURL != "" {
			u, err := url.Parse(form.ActionURL)
			if err == nil {
				targetURL = ctx.FinalURL.ResolveReference(u).String()
			}
		}

		firstStatus, firstLen, firstErr := submitFormOnce(ctx, targetURL, form.Inputs)
		secondStatus, secondLen, secondErr := submitFormOnce(ctx, targetURL, form.Inputs)
		if firstErr != nil || secondErr != nil {
			continue
		}

		firstOK := firstStatus >= 200 && firstStatus < 400
		secondOK := secondStatus >= 200 && secondStatus < 400
		diff := firstLen - secondLen
		if diff < 0 {
			diff = -diff
		}

		if firstOK && secondOK && diff < 80 {
			findings = append(findings, report.Finding{
				ID:                         "CSRF_TOKEN_REPLAY_POSSIBLE",
				Category:                   string(checks.CategoryAccessControl),
				Severity:                   report.SeverityLow,
				Confidence:                 report.ConfidenceLow,
				Validation:                 report.ValidationProbable,
				Title:                      "CSRF Token Replay Possibly Accepted",
				Message:                    "The same CSRF token appears accepted across repeated POST submissions. Verify one-time token semantics and anti-replay controls.",
				Evidence:                   fmt.Sprintf("FormAction=%s, TokenField=%s, Statuses=%d/%d, BodyLen=%d/%d", targetURL, tokenName, firstStatus, secondStatus, firstLen, secondLen),
				Fix:                        "Use per-request CSRF tokens (or strict anti-replay strategy), rotate tokens appropriately, and validate token freshness server-side.",
				IsPotentiallyFalsePositive: true,
			})
		}

		// low impact: one form check is enough
		break
	}

	return findings, nil
}

func detectCSRFTokenField(inputs []crawler.FormInput) (string, string) {
	for _, in := range inputs {
		n := strings.ToLower(strings.TrimSpace(in.Name))
		if strings.Contains(n, "csrf") || strings.Contains(n, "_token") || strings.Contains(n, "authenticity") {
			return in.Name, in.Value
		}
	}
	return "", ""
}

func submitFormOnce(ctx *ctxpkg.Context, targetURL string, inputs []crawler.FormInput) (int, int, error) {
	values := url.Values{}
	for _, in := range inputs {
		if in.Name == "" {
			continue
		}
		values.Set(in.Name, in.Value)
	}

	req, err := newScanRequest(ctx, http.MethodPost, targetURL, strings.NewReader(values.Encode()))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return 0, 0, err
	}
	body, _ := engine.DecodeResponseBody(resp)
	status := resp.StatusCode
	resp.Body.Close()
	return status, len(body), nil
}
