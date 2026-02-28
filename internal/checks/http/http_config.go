package http

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckHTTPConfiguration(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response == nil {
		return findings, nil
	}
	findings = append(findings, checkTRACEMethod(ctx)...)

	findings = append(findings, checkOPTIONSMethod(ctx)...)

	if ctx.Mode == ctxpkg.Active {
		findings = append(findings, checkPUTDELETEMethods(ctx)...)
		findings = append(findings, checkHostHeaderInjection(ctx)...)
		findings = append(findings, checkCachePoisoningActive(ctx)...)
	}

	return findings, nil
}

func checkTRACEMethod(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	if ctx.FinalURL.Scheme != "https" {
		return findings
	}

	req, err := ctxpkg.NewRequest(ctx, "TRACE", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}

	// Use a new client that doesn't follow redirects for this specific probe
	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := engine.DecodeResponseBody(resp)
		if err != nil {
			return findings
		}
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, "TRACE / HTTP/1.1") || strings.Contains(bodyString, "TRACE "+ctx.FinalURL.Path+" HTTP/1.1") {
			msg := msges.GetMessage("TRACE_METHOD_ENABLED")
			findings = append(findings, report.Finding{
				ID:       "TRACE_METHOD_ENABLED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityMedium,
				Title:    msg.Title,
				Message:  msg.Message,
				Evidence: "Server responded with 200 OK to a TRACE request.",
				Fix:      msg.Fix,
			})
		}
	}
	return findings
}

func checkOPTIONSMethod(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding

	// Make an OPTIONS request
	req, err := ctxpkg.NewRequest(ctx, "OPTIONS", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			allowedMethods := strings.Split(allowHeader, ",")
			if len(allowedMethods) > 3 {
				msg := msges.GetMessage("OPTIONS_OVER_EXPOSED")
				findings = append(findings, report.Finding{
					ID:       "OPTIONS_OVER_EXPOSED",
					Category: string(checks.CategoryHTTPProtocol),
					Severity: report.SeverityLow,
					Title:    msg.Title,
					Message:  fmt.Sprintf(msg.Message, allowHeader),
					Evidence: fmt.Sprintf("Allowed methods: %s", allowHeader),
					Fix:      msg.Fix,
				})
			}
		}
	}
	return findings
}

// checkPUTDELETEMethods checks if PUT/DELETE methods are allowed
func checkPUTDELETEMethods(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	testURL := ctx.FinalURL.String() + "/prs_test_file_" + generateRandomString(10) // Use a random file name

	// Ensure cleanup of the test file
	defer func() {
		cleanupReq, _ := ctxpkg.NewRequest(ctx, "DELETE", testURL, nil)
		ctx.HTTPClient.Do(cleanupReq)
	}()

	// Test PUT
	putReq, err := ctxpkg.NewRequest(ctx, "PUT", testURL, strings.NewReader("test_content"))
	if err != nil {
		return findings
	}
	putResp, err := ctx.HTTPClient.Do(putReq)
	if err == nil {
		defer putResp.Body.Close()
		if putResp.StatusCode >= 200 && putResp.StatusCode < 300 || putResp.StatusCode == http.StatusCreated || putResp.StatusCode == http.StatusNoContent {
			msg := msges.GetMessage("PUT_METHOD_ALLOWED")
			findings = append(findings, report.Finding{
				ID:       "PUT_METHOD_ALLOWED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, testURL),
				Evidence: fmt.Sprintf("Received status code %d for PUT request.", putResp.StatusCode),
				Fix:      msg.Fix,
			})
		}
	}

	// Test DELETE
	deleteReq, err := ctxpkg.NewRequest(ctx, "DELETE", testURL, nil)
	if err != nil {
		return findings
	}
	deleteResp, err := ctx.HTTPClient.Do(deleteReq)
	if err == nil {
		defer deleteResp.Body.Close()
		if deleteResp.StatusCode >= 200 && deleteResp.StatusCode < 300 || deleteResp.StatusCode == http.StatusAccepted || deleteResp.StatusCode == http.StatusNoContent {
			msg := msges.GetMessage("DELETE_METHOD_ALLOWED")
			findings = append(findings, report.Finding{
				ID:       "DELETE_METHOD_ALLOWED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, testURL),
				Evidence: fmt.Sprintf("Received status code %d for DELETE request.", deleteResp.StatusCode),
				Fix:      msg.Fix,
			})
		}
	}

	return findings
}

// generateRandomString generates a random string of specified length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// Placeholder for checkHTTPResponseCodes (401/403 confusion)
// This requires specific scenarios (e.g., trying authenticated vs unauthenticated access to a protected resource)
// func checkHTTPResponseCodes(ctx *checks.Context) []report.Finding {
// 	return nil
// }

// Placeholder for checkChunkedEncoding (vulnerable chunked encoding)
// This is very low-level and hard to detect without custom TCP packet inspection.
// func checkChunkedEncoding(ctx *checks.Context) []report.Finding {
// 	return nil
// }

// Placeholder for checkHTTP2Configuration (HTTP/2 misconfigurations)
// This might involve checking ALPN, or trying to negotiate HTTP/2 explicitly.
// func checkHTTP2Configuration(ctx *checks.Context) []report.Finding {
// 	return nil
// }
