package deserialization

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var (
	phpObjectPattern = regexp.MustCompile(`^[OCaidsbN]:\d+[:;{]`)
)

func CheckInsecureDeserialization(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Active Mode: Payload Injection (Optional/Safe check)
	if ctx.Mode == ctxpkg.Active {
		// TODO: Implement safe gadget probe (e.g., sleep or specific echo)
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	for param, values := range u.Query() {
		for _, val := range values {
			if isSerializedData(val) {
				findings = append(findings, createFinding(param, "Query Parameter"))
			}
		}
	}

	if ctx.Response != nil {
		for _, cookie := range ctx.Response.Cookies() {
			if isSerializedData(cookie.Value) {
				findings = append(findings, createFinding(cookie.Name, "Cookie"))
			}
		}
	}

	return findings, nil
}

func isSerializedData(value string) bool {
	// 0. Try URL Decode first
	if unescaped, err := url.QueryUnescape(value); err == nil && unescaped != value {
		value = unescaped
	}

	// 1. Check for Base64 encoding first
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil && len(decoded) > 4 {
		if checkSignatures(string(decoded)) {
			return true
		}
	}

	// 2. Check for Hex encoding
	if decodedHex, err := hex.DecodeString(value); err == nil && len(decodedHex) > 4 {
		if checkSignatures(string(decodedHex)) {
			return true
		}
	}

	// 3. Check raw string
	return checkSignatures(value)
}

func checkSignatures(value string) bool {
	// Java Serialization: AC ED 00 05
	// Stricter: Look for 'sr' (0x73 0x72) which is TC_CLASSDESC often following magic bytes
	if strings.HasPrefix(value, "\xac\xed\x00\x05") && strings.Contains(value, "\x73\x72") {
		return true
	}

	// PHP Serialization
	if phpObjectPattern.MatchString(value) {
		// Simple heuristic for PHP object or array
		return true
	}

	// Python Pickle
	// Stricter: "cos" + "system" + "R" (REDUCE opcode) or specific protocol versions
	if (strings.Contains(value, "cos") && strings.Contains(value, "system") && strings.Contains(value, "R")) ||
		strings.HasPrefix(value, "\x80\x03") || strings.HasPrefix(value, "\x80\x04") {
		return true
	}

	return false
}

func createFinding(name, source string) report.Finding {
	msg := msges.GetMessage("INSECURE_DESERIALIZATION_SUSPECTED")
	return report.Finding{
		ID:                         "INSECURE_DESERIALIZATION_SUSPECTED",
		Category:                   string(checks.CategoryIntegrityFailures),
		Severity:                   report.SeverityHigh,
		Confidence:                 report.ConfidenceMedium,
		Title:                      msg.Title,
		Message:                    fmt.Sprintf(msg.Message, fmt.Sprintf("%s (%s)", name, source)),
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
	}
}
