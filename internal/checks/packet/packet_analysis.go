package packet

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	ssnRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// creditCardRegex = ... (omitted for brevity/safety, can be added)
)

type CanonicalPacket struct {
	ReqAuthorization string
	ReqCookie        string
	ReqOrigin        string
	ReqReferer       string
	ReqAccept        string
	RespContentType  string
	RespWWWAuth      string
	RespCORSOrigin   string
	RespCORSCreds    string
}

func CheckPacketAnomalies(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	packet := extractCanonical(ctx)

	if len(ctx.BodyBytes) > 0 && packet.RespContentType != "" {
		detectedType := http.DetectContentType(ctx.BodyBytes)

		simpleDetected := strings.Split(detectedType, ";")[0]
		simpleHeader := strings.Split(packet.RespContentType, ";")[0]

		if simpleHeader == "application/json" && strings.Contains(simpleDetected, "html") {
			evidence := fmt.Sprintf("Header: %s, Detected: %s", simpleHeader, simpleDetected)
			msg := msges.GetMessage("PACKET_CONTENT_TYPE_MISMATCH")
			findings = append(findings, report.Finding{
				ID:         "PACKET_CONTENT_TYPE_MISMATCH",
				Category:   string(checks.CategoryHTTPProtocol),
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceHigh,
				Title:      msg.Title,
				Message:    fmt.Sprintf(msg.Message, simpleHeader, simpleDetected),
				Evidence:   evidence,
				Fix:        msg.Fix,
			})
		}
	}

	if ctx.Response.StatusCode == http.StatusOK && packet.RespWWWAuth != "" {
		msg := msges.GetMessage("PACKET_WWW_AUTHENTICATE_ON_200")
		findings = append(findings, report.Finding{
			ID:         "PACKET_WWW_AUTHENTICATE_ON_200",
			Category:   string(checks.CategoryAuthSession),
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceHigh,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	if packet.RespCORSOrigin == "*" && packet.RespCORSCreds == "true" {
		msg := msges.GetMessage("PACKET_CORS_BAD_COMBINATION")
		findings = append(findings, report.Finding{
			ID:         "PACKET_CORS_BAD_COMBINATION",
			Category:   string(checks.CategoryNetwork),
			Severity:   report.SeverityMedium,
			Confidence: report.ConfidenceHigh,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	if strings.Contains(packet.ReqAccept, "application/json") &&
		!strings.Contains(packet.ReqAccept, "text/html") && // Ensure it didn't accept HTML too
		strings.Contains(packet.RespContentType, "text/html") {

		msg := msges.GetMessage("PACKET_ACCEPT_IGNORED")
		findings = append(findings, report.Finding{
			ID:         "PACKET_ACCEPT_IGNORED",
			Category:   string(checks.CategoryHTTPProtocol),
			Severity:   report.SeverityInfo,
			Confidence: report.ConfidenceMedium,
			Title:      msg.Title,
			Message:    fmt.Sprintf(msg.Message, packet.ReqAccept, packet.RespContentType),
			Fix:        msg.Fix,
		})
	}

	// Cache-Control Check
	cc := ctx.Response.Header.Get("Cache-Control")
	if cc == "" || (!strings.Contains(cc, "no-store") && !strings.Contains(cc, "private")) {
		// Only for sensitive content types
		if strings.Contains(packet.RespContentType, "application/json") {
			// findings = append(...) // Add finding if needed
		}
	}

	// PII Leakage Check (Regex on Body)
	bodyString := string(ctx.BodyBytes)
	if emailRegex.MatchString(bodyString) {
		match := emailRegex.FindString(bodyString)
		// Simple filter to avoid FP on example emails
		if !strings.Contains(match, "example.com") {
			findings = append(findings, report.Finding{
				ID:         "PII_LEAKAGE_EMAIL",
				Category:   string(checks.CategoryInformationLeakage),
				Severity:   report.SeverityInfo,
				Confidence: report.ConfidenceMedium,
				Title:      "Email Address Leaked",
				Message:    "Potential email address found in response body.",
				Evidence:   match,
				Fix:        "Ensure PII is not leaked in responses.",
			})
		}
	}
	if ssnMatch := ssnRegex.FindString(bodyString); ssnMatch != "" && isLikelySSN(ssnMatch) {
		findings = append(findings, report.Finding{
			ID:         "PII_LEAKAGE_SSN",
			Category:   string(checks.CategoryInformationLeakage),
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceMedium,
			Title:      "SSN Leaked",
			Message:    "Potential Social Security Number found in response body.",
			Evidence:   ssnMatch,
			Fix:        "Ensure PII is not leaked in responses.",
		})
	}

	return findings, nil
}

func isLikelySSN(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	area, err1 := strconv.Atoi(parts[0])
	group, err2 := strconv.Atoi(parts[1])
	serial, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	return true
}

func extractCanonical(ctx *ctxpkg.Context) CanonicalPacket {
	p := CanonicalPacket{}

	// Request Fields
	if ctx.Response != nil && ctx.Response.Request != nil {
		req := ctx.Response.Request
		p.ReqAuthorization = req.Header.Get("Authorization")
		p.ReqCookie = req.Header.Get("Cookie")
		p.ReqOrigin = req.Header.Get("Origin")
		p.ReqReferer = req.Header.Get("Referer")
		p.ReqAccept = req.Header.Get("Accept")
	}

	// Response Fields
	if ctx.Response != nil {
		p.RespContentType = ctx.Response.Header.Get("Content-Type")
		p.RespWWWAuth = ctx.Response.Header.Get("WWW-Authenticate")
		p.RespCORSOrigin = ctx.Response.Header.Get("Access-Control-Allow-Origin")
		p.RespCORSCreds = ctx.Response.Header.Get("Access-Control-Allow-Credentials")
	}

	return p
}
