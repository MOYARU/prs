package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MOYARU/prs/internal/app/ui"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/registry"
	"github.com/MOYARU/prs/internal/checks/scanner"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

var progressMu sync.Mutex

// PrintScanProgress updates the current scan progress on the same line.
func PrintScanProgress(current, total int, checkName, target string) {
	progressMu.Lock()
	defer progressMu.Unlock()

	if total <= 0 {
		fmt.Printf("\r [------------------------------] 0%% | %s [0/0]: %s\033[K", checkName, target)
		return
	}

	percentage := float64(current) / float64(total) * 100
	// Truncate target URL to prevent line wrapping
	if len(target) > 50 {
		target = target[:47] + "..."
	}
	width := 30
	filled := int(float64(width) * (float64(current) / float64(total)))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	fmt.Printf("\r [%s] %.0f%% | %s [%d/%d]: %s\033[K", bar, percentage, checkName, current, total, target)
}

// printFindings prints the scan findings to the console with appropriate formatting and colors.
func PrintFindings(findings []report.Finding) {
	if len(findings) == 0 {
		fmt.Printf("%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("ConsoleNoIssues"), ui.ColorReset)
		return
	}

	aggregated := aggregateFindingsForConsole(findings)

	// Sort findings by severity (High -> Medium -> Low -> Info)
	sort.Slice(aggregated, func(i, j int) bool {
		if severityWeight(aggregated[i].Finding.Severity) == severityWeight(aggregated[j].Finding.Severity) {
			if aggregated[i].Finding.Category == aggregated[j].Finding.Category {
				return aggregated[i].Finding.Title < aggregated[j].Finding.Title
			}
			return aggregated[i].Finding.Category < aggregated[j].Finding.Category
		}
		return severityWeight(aggregated[i].Finding.Severity) > severityWeight(aggregated[j].Finding.Severity)
	})

	fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ConsoleFindingsTitle"), ui.ColorReset)
	for _, item := range aggregated {
		f := item.Finding
		var severityColor string
		switch f.Severity {
		case "INFO":
			severityColor = ui.ColorInfo
		case "LOW":
			severityColor = ui.ColorLow
		case "MEDIUM":
			severityColor = ui.ColorMedium
		case "HIGH":
			severityColor = ui.ColorHigh
		default:
			severityColor = ui.ColorWhite
		}

		// Localize finding details
		title, message, fix := f.Title, f.Message, f.Fix

		fmt.Printf("\n%s[%s] (%s) %s%s\n", severityColor, f.Severity, f.Category, title, ui.ColorReset)
		if item.Count > 1 {
			fmt.Printf("%s - Occurrences: %d%s\n", ui.ColorGray, item.Count, ui.ColorReset)
		}
		fmt.Printf("%s - %s%s\n", ui.ColorGray, message, ui.ColorReset)
		if f.Evidence != "" {
			fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleEvidenceLabel"), f.Evidence, ui.ColorReset)
		}
		fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleFixLabel"), fix, ui.ColorReset)
		if f.Confidence != "" { // Only print confidence if it's provided
			fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleConfidenceLabel"), f.Confidence, ui.ColorReset)
		}
		if f.EvidenceQuality > 0 {
			fmt.Printf("%s - Evidence Quality: %d/100%s\n", ui.ColorGray, f.EvidenceQuality, ui.ColorReset)
		}
		if f.Validation != "" {
			fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleValidationLabel"), f.Validation, ui.ColorReset)
		}
		if len(f.AffectedURLs) > 0 {
			fmt.Printf("%s - Affected URLs:%s\n", ui.ColorGray, ui.ColorReset)
			for _, u := range f.AffectedURLs {
				fmt.Printf("%s   - %s%s\n", ui.ColorGray, u, ui.ColorReset)
			}
		}
	}
}

type consoleFinding struct {
	Finding report.Finding
	Count   int
}

func aggregateFindingsForConsole(findings []report.Finding) []consoleFinding {
	type key struct {
		ID       string
		Severity report.Severity
		Category string
		Title    string
	}

	grouped := make(map[key]*consoleFinding)
	for _, f := range findings {
		k := key{
			ID:       f.ID,
			Severity: f.Severity,
			Category: f.Category,
			Title:    f.Title,
		}

		if _, ok := grouped[k]; !ok {
			cp := f
			cp.AffectedURLs = uniqueSortedStrings(cp.AffectedURLs)
			grouped[k] = &consoleFinding{
				Finding: cp,
				Count:   1,
			}
			continue
		}

		grouped[k].Count++
		existing := grouped[k].Finding
		if existing.Evidence == "" && f.Evidence != "" {
			existing.Evidence = f.Evidence
		}
		if existing.Confidence == "" && f.Confidence != "" {
			existing.Confidence = f.Confidence
		}
		if existing.Validation == "" && f.Validation != "" {
			existing.Validation = f.Validation
		}
		if f.EvidenceQuality > existing.EvidenceQuality {
			existing.EvidenceQuality = f.EvidenceQuality
		}
		existing.AffectedURLs = append(existing.AffectedURLs, f.AffectedURLs...)
		existing.AffectedURLs = uniqueSortedStrings(existing.AffectedURLs)
		grouped[k].Finding = existing
	}

	out := make([]consoleFinding, 0, len(grouped))
	for _, v := range grouped {
		out = append(out, *v)
	}
	return out
}

func uniqueSortedStrings(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func SaveJSONReport(target string, scannedURLs []string, findings []report.Finding, checkStats map[string]scanner.CheckStat, startTime, endTime time.Time) error {
	type Summary struct {
		High   int `json:"high"`
		Medium int `json:"medium"`
		Low    int `json:"low"`
		Info   int `json:"info"`
		Total  int `json:"total"`
	}

	type JSONReport struct {
		Target      string           `json:"target"`
		ScannedURLs []string         `json:"scanned_urls"`
		StartTime   time.Time        `json:"start_time"`
		EndTime     time.Time        `json:"end_time"`
		Summary     Summary          `json:"summary"`
		CheckStats  map[string]any   `json:"check_stats,omitempty"`
		Findings    []report.Finding `json:"findings"`
	}

	summary := Summary{}
	for _, f := range findings {
		switch f.Severity {
		case report.SeverityHigh:
			summary.High++
		case report.SeverityMedium:
			summary.Medium++
		case report.SeverityLow:
			summary.Low++
		case report.SeverityInfo:
			summary.Info++
		}
	}
	summary.Total = len(findings)

	stats := make(map[string]any)
	for id, st := range checkStats {
		stats[id] = map[string]any{
			"requests":          st.Requests,
			"request_time_ms":   st.Duration.Milliseconds(),
			"request_time_text": st.Duration.String(),
		}
	}

	reportData := JSONReport{
		Target:      target,
		ScannedURLs: scannedURLs,
		StartTime:   startTime,
		EndTime:     endTime,
		Summary:     summary,
		CheckStats:  stats,
		Findings:    findings,
	}

	timestamp := time.Now().Format("20060102_150405")
	sanitizedTarget := strings.ReplaceAll(target, "://", "_")
	sanitizedTarget = strings.ReplaceAll(sanitizedTarget, "/", "_")
	sanitizedTarget = strings.ReplaceAll(sanitizedTarget, ":", "_")

	filename := fmt.Sprintf("prs_report_%s_%s.json", sanitizedTarget, timestamp)

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(reportData); err != nil {
		return err
	}

	fmt.Printf("\n%s\n", msges.GetUIMessage("JSONReportSaved", filename))
	return nil
}

// PrintScanSummary prints a summary of all performed checks
func PrintScanSummary(checkCounts map[string]int, checksRan map[string]bool, findingsByCheck map[string][]report.Finding) {
	fmt.Println()
	fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ConsoleScanSummaryTitle"), ui.ColorReset)

	for _, check := range registry.DefaultChecks() {
		ran := checksRan[check.ID]
		count := checkCounts[check.ID]

		checkTitle := check.Title
		msg := msges.GetMessage(check.ID)
		if msg.Title != "Message Not Found" {
			checkTitle = msg.Title
		}

		var status, color string
		if !ran {
			if check.Mode == ctxpkg.Active {
				status = msges.GetUIMessage("ConsoleActiveModeRequired")
			} else {
				status = msges.GetUIMessage("ConsoleSkipped")
			}
			color = ui.ColorGray
		} else if count > 0 {
			status = msges.GetUIMessage("CheckStatusFound")
			color = ui.ColorRed
		} else {
			status = msges.GetUIMessage("CheckStatusNotFound")
			color = ui.ColorGreen
		}

		fmt.Printf(" [%s] %s%s%s\n", status, color, checkTitle, ui.ColorReset)

		if count > 0 {
			findings := findingsByCheck[check.ID]
			summaryItems := aggregateSummaryItems(findings)

			sort.Slice(summaryItems, func(i, j int) bool {
				if severityWeight(summaryItems[i].Severity) == severityWeight(summaryItems[j].Severity) {
					if summaryItems[i].Count == summaryItems[j].Count {
						return summaryItems[i].Title < summaryItems[j].Title
					}
					return summaryItems[i].Count > summaryItems[j].Count
				}
				return severityWeight(summaryItems[i].Severity) > severityWeight(summaryItems[j].Severity)
			})

			const maxSummaryItemsPerCheck = 8
			limit := len(summaryItems)
			if limit > maxSummaryItemsPerCheck {
				limit = maxSummaryItemsPerCheck
			}

			for i := 0; i < limit; i++ {
				item := summaryItems[i]
				prefix := " \t|--"
				if i == limit-1 {
					prefix = " \t`--"
				}

				sevColor := ui.ColorWhite
				switch item.Severity {
				case report.SeverityHigh:
					sevColor = ui.ColorHigh
				case report.SeverityMedium:
					sevColor = ui.ColorMedium
				case report.SeverityLow:
					sevColor = ui.ColorLow
				case report.SeverityInfo:
					sevColor = ui.ColorInfo
				}

				if item.Count > 1 {
					fmt.Printf("%s %s[%s] %s (x%d)%s\n", prefix, sevColor, item.Severity, item.Title, item.Count, ui.ColorReset)
				} else {
					fmt.Printf("%s %s[%s] %s%s\n", prefix, sevColor, item.Severity, item.Title, ui.ColorReset)
				}
			}

			remaining := len(summaryItems) - limit
			if remaining > 0 {
				fmt.Printf(" \t`-- %s... and %d more issue types%s\n", ui.ColorGray, remaining, ui.ColorReset)
			}
		}
	}
}

type summaryItem struct {
	Severity report.Severity
	Title    string
	Count    int
}

func aggregateSummaryItems(findings []report.Finding) []summaryItem {
	type summaryKey struct {
		ID       string
		Severity report.Severity
		Title    string
	}

	summaryMap := make(map[summaryKey]int)
	for _, f := range findings {
		k := summaryKey{
			ID:       f.ID,
			Severity: f.Severity,
			Title:    f.Title,
		}
		summaryMap[k]++
	}

	items := make([]summaryItem, 0, len(summaryMap))
	for k, c := range summaryMap {
		items = append(items, summaryItem{
			Severity: k.Severity,
			Title:    k.Title,
			Count:    c,
		})
	}
	return items
}

func severityWeight(s report.Severity) int {
	switch s {
	case report.SeverityHigh:
		return 3
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 1
	case report.SeverityInfo:
		return 0
	default:
		return -1
	}
}
