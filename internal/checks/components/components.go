package components

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var (
	commentRegex        = regexp.MustCompile(`<!--.*?v?(\d+\.\d+(\.\d+)?).*?-->`)
	metaRegex           = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	scriptRegex         = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	componentSignatures = []struct {
		Name        string
		SafeVersion string
		Pattern     *regexp.Regexp
	}{
		{Name: "apache", SafeVersion: "2.4.58", Pattern: regexp.MustCompile(`(?i)apache(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`)},
		{Name: "nginx", SafeVersion: "1.24.0", Pattern: regexp.MustCompile(`(?i)nginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`)},
		{Name: "php", SafeVersion: "8.1.0", Pattern: regexp.MustCompile(`(?i)\bphp(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`)},
		{Name: "jquery", SafeVersion: "3.6.0", Pattern: regexp.MustCompile(`(?i)jquery(?:[-._]|%2d)?(\d+\.\d+(?:\.\d+)?)`)},
		{Name: "wordpress", SafeVersion: "6.0.0", Pattern: regexp.MustCompile(`(?i)wordpress(?:\s+|/)?(\d+\.\d+(?:\.\d+)?)`)},
	}
)

func CheckVulnerableComponents(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	headersToCheck := map[string]string{
		"Server":       ctx.Response.Header.Get("Server"),
		"X-Powered-By": ctx.Response.Header.Get("X-Powered-By"),
	}
	seen := make(map[string]struct{})

	for header, value := range headersToCheck {
		for _, detail := range findOutdatedComponents(value) {
			key := header + "|" + detail
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, createFinding(fmt.Sprintf("%s Header: %s", header, detail)))
		}
	}

	bodyString := string(ctx.BodyBytes)

	// Check HTML Comments
	matches := commentRegex.FindAllStringSubmatch(bodyString, -1)
	for _, match := range matches {
		fullComment := match[0]
		for _, detail := range findOutdatedComponents(fullComment) {
			key := "comment|" + detail
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, createFinding(fmt.Sprintf("HTML Comment: %s", detail)))
		}
	}

	// Check Meta Generator
	metaMatches := metaRegex.FindAllStringSubmatch(bodyString, -1)
	for _, match := range metaMatches {
		content := match[1]
		for _, detail := range findOutdatedComponents(content) {
			key := "meta|" + detail
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, createFinding(fmt.Sprintf("Meta Generator: %s", detail)))
		}
	}

	// Check Script Src
	scriptMatches := scriptRegex.FindAllStringSubmatch(bodyString, -1)
	for _, match := range scriptMatches {
		src := match[1]
		for _, detail := range findOutdatedComponents(src) {
			key := "script|" + detail
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, createFinding(fmt.Sprintf("Script Source: %s", detail)))
		}
	}

	return findings, nil
}

func findOutdatedComponents(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var details []string
	for _, sig := range componentSignatures {
		matches := sig.Pattern.FindAllStringSubmatch(strings.ToLower(text), -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			version := strings.TrimSpace(m[1])
			if version == "" {
				continue
			}
			if compareVersions(version, sig.SafeVersion) < 0 {
				detail := fmt.Sprintf("%s %s (< %s)", sig.Name, version, sig.SafeVersion)
				if _, ok := seen[detail]; ok {
					continue
				}
				seen[detail] = struct{}{}
				details = append(details, detail)
			}
		}
	}
	sort.Strings(details)
	return details
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
