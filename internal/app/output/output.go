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

	// Sort findings by severity (High -> Medium -> Low -> Info)
	sort.Slice(findings, func(i, j int) bool {
		return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
	})

	fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ConsoleFindingsTitle"), ui.ColorReset)
	for _, f := range findings {
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
		fmt.Printf("%s - %s%s\n", ui.ColorGray, message, ui.ColorReset)
		if f.Evidence != "" {
			fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleEvidenceLabel"), f.Evidence, ui.ColorReset)
		}
		fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleFixLabel"), fix, ui.ColorReset)
		if f.Confidence != "" { // Only print confidence if it's provided
			fmt.Printf("%s - %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleConfidenceLabel"), f.Confidence, ui.ColorReset)
		}
		if len(f.AffectedURLs) > 0 {
			fmt.Printf("%s - Affected URLs:%s\n", ui.ColorGray, ui.ColorReset)
			for _, u := range f.AffectedURLs {
				fmt.Printf("%s   - %s%s\n", ui.ColorGray, u, ui.ColorReset)
			}
		}
	}
}

func SaveJSONReport(target string, scannedURLs []string, findings []report.Finding, startTime, endTime time.Time) error {
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

	reportData := JSONReport{
		Target:      target,
		ScannedURLs: scannedURLs,
		StartTime:   startTime,
		EndTime:     endTime,
		Summary:     summary,
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
			for i, f := range findings {
				prefix := " \t|--"
				if i == len(findings)-1 {
					prefix = " \t`--"
				}

				sevColor := ui.ColorWhite
				switch f.Severity {
				case report.SeverityHigh:
					sevColor = ui.ColorHigh
				case report.SeverityMedium:
					sevColor = ui.ColorMedium
				case report.SeverityLow:
					sevColor = ui.ColorLow
				case report.SeverityInfo:
					sevColor = ui.ColorInfo
				}

				fmt.Printf("%s %s[%s] %s%s\n", prefix, sevColor, f.Severity, f.Title, ui.ColorReset)
			}
		}
	}
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
