package input

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

var traversalPayloads = []string{
	"../../../../etc/passwd",
	"..%2f..%2f..%2f..%2fetc%2fpasswd",
	"..\\..\\..\\..\\windows\\win.ini",
	"..%5c..%5c..%5c..%5cwindows%5cwin.ini",
}

var traversalKeywords = []string{
	"root:x:0:0:",
	"[extensions]",
	"[fonts]",
}

func CheckPathTraversal(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx == nil || ctx.Mode != ctxpkg.Active || ctx.FinalURL == nil || ctx.HTTPClient == nil {
		return findings, nil
	}

	u, err := url.Parse(ctx.FinalURL.String())
	if err != nil {
		return findings, nil
	}
	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	baselineBody := strings.ToLower(string(ctx.BodyBytes))
	found := map[string]bool{}

	for param, values := range query {
		if len(values) == 0 {
			continue
		}

		nameLower := strings.ToLower(param)
		if !strings.Contains(nameLower, "file") &&
			!strings.Contains(nameLower, "path") &&
			!strings.Contains(nameLower, "template") &&
			!strings.Contains(nameLower, "page") &&
			!strings.Contains(nameLower, "include") &&
			!strings.Contains(nameLower, "download") {
			continue
		}

		for _, payload := range traversalPayloads {
			newQuery := cloneValues(query)
			newQuery.Set(param, payload)
			u.RawQuery = newQuery.Encode()

			req, err := ctxpkg.NewRequest(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				continue
			}
			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, _ := engine.DecodeResponseBody(resp)
			resp.Body.Close()

			bodyLower := strings.ToLower(string(bodyBytes))
			for _, kw := range traversalKeywords {
				if strings.Contains(bodyLower, kw) && !strings.Contains(baselineBody, kw) {
					if found[param] {
						break
					}
					found[param] = true
					findings = append(findings, report.Finding{
						ID:                         "PATH_TRAVERSAL_POSSIBLE",
						Category:                   string(checks.CategoryInputHandling),
						Severity:                   report.SeverityHigh,
						Confidence:                 report.ConfidenceMedium,
						Title:                      "Path Traversal Possible",
						Message:                    fmt.Sprintf("Parameter '%s' appears to allow path traversal file access.", param),
						Evidence:                   fmt.Sprintf("Payload=%q, Keyword=%q, URL=%s", payload, kw, u.String()),
						Fix:                        "Normalize and validate file paths server-side, enforce allowlisted base directories, and block traversal sequences (../, ..\\).",
						IsPotentiallyFalsePositive: true,
					})
					break
				}
			}
		}
	}

	return findings, nil
}

func cloneValues(v url.Values) url.Values {
	dst := make(url.Values, len(v))
	for k, vv := range v {
		dst[k] = append([]string(nil), vv...)
	}
	return dst
}
