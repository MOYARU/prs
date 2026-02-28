package web

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/report"
)

// CheckFileUploadBypassActive performs a low-impact file-upload acceptance signal check.
func CheckFileUploadBypassActive(ctx *ctxpkg.Context) ([]report.Finding, error) {
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
	formAction, fileField, ok := findUploadForm(doc)
	if !ok {
		return findings, nil
	}

	target := ctx.FinalURL.String()
	if formAction != "" {
		u, err := url.Parse(formAction)
		if err == nil {
			target = ctx.FinalURL.ResolveReference(u).String()
		}
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile(fileField, "prs_test.php.jpg")
	if err != nil {
		return findings, nil
	}
	_, _ = fw.Write([]byte("<?php echo 'PRS_UPLOAD_TEST'; ?>"))
	_ = w.WriteField("submit", "upload")
	_ = w.Close()

	req, err := ctxpkg.NewRequest(ctx, http.MethodPost, target, &body)
	if err != nil {
		return findings, nil
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings, nil
	}
	respBody, _ := ioReadAllLimited(resp.Body, 256*1024)
	lower := strings.ToLower(string(respBody))
	loc := strings.ToLower(resp.Header.Get("Location"))

	if (resp.StatusCode >= 200 && resp.StatusCode < 400) &&
		(strings.Contains(lower, "upload") || strings.Contains(lower, "success") || strings.Contains(lower, "prs_test.php.jpg") || strings.Contains(loc, "prs_test.php.jpg")) {
		baseFinding := report.Finding{
			ID:                         "FILE_UPLOAD_BYPASS_POSSIBLE",
			Category:                   string(checks.CategoryFileExposure),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceLow,
			Validation:                 report.ValidationProbable,
			Title:                      "File Upload Bypass Signal",
			Message:                    "A suspicious double-extension upload appears accepted. Verify server-side file type validation and executable upload handling.",
			Evidence:                   fmt.Sprintf("Action=%s, Field=%s, Filename=prs_test.php.jpg, Status=%d", target, fileField, resp.StatusCode),
			Fix:                        "Enforce allowlisted extensions/MIME signatures server-side, store outside web root, and block executable content in upload paths.",
			IsPotentiallyFalsePositive: true,
		}
		findings = append(findings, baseFinding)

		// Second-step confirmation: check whether uploaded test file becomes web-accessible.
		if execURL, ok := probeUploadedFileAccess(ctx, "prs_test.php.jpg"); ok {
			findings = append(findings, report.Finding{
				ID:                         "FILE_UPLOAD_EXECUTION_POSSIBLE",
				Category:                   string(checks.CategoryFileExposure),
				Severity:                   report.SeverityHigh,
				Confidence:                 report.ConfidenceHigh,
				Validation:                 report.ValidationConfirmed,
				Title:                      "Uploaded File Accessible from Web Path",
				Message:                    "Uploaded test file appears accessible via web path, indicating potentially dangerous upload handling.",
				Evidence:                   fmt.Sprintf("Accessible URL=%s (filename=prs_test.php.jpg)", execURL),
				Fix:                        "Store uploads outside web root, randomize storage names, deny script execution in upload directories, and enforce extension + MIME + content validation.",
				IsPotentiallyFalsePositive: false,
			})
		}
	}

	return findings, nil
}

func findUploadForm(doc *html.Node) (action string, fileField string, ok bool) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if ok || n == nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			method := "GET"
			formAction := ""
			for _, a := range n.Attr {
				if a.Key == "method" {
					method = strings.ToUpper(strings.TrimSpace(a.Val))
				}
				if a.Key == "action" {
					formAction = strings.TrimSpace(a.Val)
				}
			}
			if method == "POST" {
				field := findFileInputName(n)
				if field != "" {
					action, fileField, ok = formAction, field, true
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return action, fileField, ok
}

func findFileInputName(form *html.Node) string {
	var name string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if name != "" || n == nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "input" {
			typ := ""
			nm := ""
			for _, a := range n.Attr {
				if a.Key == "type" {
					typ = strings.ToLower(strings.TrimSpace(a.Val))
				}
				if a.Key == "name" {
					nm = strings.TrimSpace(a.Val)
				}
			}
			if typ == "file" && nm != "" {
				name = nm
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
	return name
}

func ioReadAllLimited(rc io.ReadCloser, n int64) ([]byte, error) {
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, n))
}

func probeUploadedFileAccess(ctx *ctxpkg.Context, filename string) (string, bool) {
	if ctx == nil || ctx.FinalURL == nil || ctx.HTTPClient == nil {
		return "", false
	}
	candidates := []string{
		"/uploads/" + filename,
		"/upload/" + filename,
		"/files/" + filename,
		"/static/uploads/" + filename,
		"/media/" + filename,
	}
	for _, p := range candidates {
		u := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + p
		req, err := ctxpkg.NewRequest(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		b, _ := ioReadAllLimited(resp.Body, 128*1024)
		body := strings.ToLower(string(b))
		if resp.StatusCode == http.StatusOK && (strings.Contains(body, "prs_upload_test") || strings.Contains(body, filename)) {
			return u, true
		}
	}
	return "", false
}
