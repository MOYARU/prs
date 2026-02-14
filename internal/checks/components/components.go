package components

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var (
	commentRegex = regexp.MustCompile(`<!--.*?v?(\d+\.\d+(\.\d+)?).*?-->`)
	metaRegex    = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	scriptRegex  = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	// Simple version check map: Software Name -> Min Safe Version
	safeVersions = map[string]string{
		"apache": "2.4.50",
		"nginx":  "1.20.0",
		"php":    "8.0.0",
		"jquery": "3.5.0",
	}
)

func CheckVulnerableComponents(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	headersToCheck := map[string]string{
		"Server":       ctx.Response.Header.Get("Server"),
		"X-Powered-By": ctx.Response.Header.Get("X-Powered-By"),
	}

	for header, value := range headersToCheck {
		if value != "" {
			if isOutdated(value) {
				findings = append(findings, createFinding(fmt.Sprintf("%s Header: %s", header, value)))
			}
		}
	}

	bodyString := string(ctx.BodyBytes)

	// Check HTML Comments
	matches := commentRegex.FindAllStringSubmatch(bodyString, -1)
	for _, match := range matches {
		fullComment := match[0]
		if isOutdated(fullComment) {
			findings = append(findings, createFinding(fmt.Sprintf("HTML Comment: %s", fullComment)))
		}
	}

	// Check Meta Generator
	metaMatches := metaRegex.FindAllStringSubmatch(bodyString, -1)
	for _, match := range metaMatches {
		content := match[1]
		if isOutdated(content) {
			findings = append(findings, createFinding(fmt.Sprintf("Meta Generator: %s", content)))
		}
	}

	// Check Script Src
	scriptMatches := scriptRegex.FindAllStringSubmatch(bodyString, -1)
	for _, match := range scriptMatches {
		src := match[1]
		// Simple heuristic: check if src contains version numbers
		if isOutdated(src) {
			findings = append(findings, createFinding(fmt.Sprintf("Script Source: %s", src)))
		}
	}

	return findings, nil
}

func isOutdated(versionStr string) bool {
	v := strings.ToLower(versionStr)

	for software, safeVer := range safeVersions {
		if strings.Contains(v, software) {
			// Extract version from string (simple regex)
			verRegex := regexp.MustCompile(`(\d+\.\d+(\.\d+)?)`)
			verMatch := verRegex.FindString(v)
			if verMatch != "" {
				if compareVersions(verMatch, safeVer) < 0 {
					return true
				}
			}
		}
	}
	return false
}

func compareVersions(v1, v2 string) int {
	// Simple version comparison
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &n2)
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}

func createFinding(info string) report.Finding {
	msg := msges.GetMessage("COMPONENT_OUTDATED_DETECTED")
	return report.Finding{
		ID:                         "COMPONENT_OUTDATED_DETECTED",
		Category:                   string(checks.CategoryVulnerableComponents),
		Severity:                   report.SeverityMedium,
		Confidence:                 report.ConfidenceMedium,
		Title:                      msg.Title,
		Message:                    fmt.Sprintf(msg.Message, info),
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
	}
}
