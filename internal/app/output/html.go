package output

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"time"

	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

type TemplateFinding struct {
	report.Finding
	Description  string
	AffectedURLs []string
}

// HTML report
type HTMLReportData struct {
	Target      string
	ScannedURLs []string
	ScanTime    string
	Duration    string
	TotalIssues int
	HighCount   int
	MediumCount int
	LowCount    int
	InfoCount   int
	Findings    []TemplateFinding

	UITitle              string
	UITarget             string
	UIScanTime           string
	UIDuration           string
	UIHigh               string
	UIMedium             string
	UILow                string
	UIInfo               string
	UICrawledScope       string
	UIFindings           string
	UIRecommendation     string
	UIChartTitle         string
	UIEvidence           string
	UIManualVerification string
	UINoVulns            string
}

// SaveHTML report generates and saves an HTML report to a file.
func SaveHTMLReport(target string, scannedURLs []string, findings []report.Finding, startTime, endTime time.Time) error {
	filename := fmt.Sprintf("prs_report_%s.html", time.Now().Format("20060102_150405"))

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Sort findings by severity (High -> Medium -> Low -> Info)
	sort.Slice(findings, func(i, j int) bool {
		return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
	})

	templateFindings := make([]TemplateFinding, len(findings))
	for i, f := range findings {
		templateFindings[i] = TemplateFinding{
			Finding:      f,
			Description:  f.Message,
			AffectedURLs: f.AffectedURLs,
		}
	}

	data := HTMLReportData{
		Target:               target,
		ScannedURLs:          scannedURLs,
		ScanTime:             startTime.Format("2006-01-02 15:04:05"),
		Duration:             endTime.Sub(startTime).String(),
		Findings:             templateFindings,
		UITitle:              msges.GetUIMessage("HTMLReportTitle"),
		UITarget:             msges.GetUIMessage("HTMLTarget"),
		UIScanTime:           msges.GetUIMessage("HTMLScanTime"),
		UIDuration:           msges.GetUIMessage("HTMLDuration"),
		UIHigh:               msges.GetUIMessage("HTMLHigh"),
		UIMedium:             msges.GetUIMessage("HTMLMedium"),
		UILow:                msges.GetUIMessage("HTMLLow"),
		UIInfo:               msges.GetUIMessage("HTMLInfo"),
		UICrawledScope:       msges.GetUIMessage("HTMLCrawledScope"),
		UIFindings:           msges.GetUIMessage("HTMLFindings"),
		UIRecommendation:     msges.GetUIMessage("HTMLRecommendation"),
		UIChartTitle:         msges.GetUIMessage("HTMLChartTitle"),
		UIEvidence:           msges.GetUIMessage("ConsoleEvidenceLabel"),
		UIManualVerification: msges.GetUIMessage("UIManualVerification"),
		UINoVulns:            msges.GetUIMessage("ConsoleNoIssues"),
	}

	for _, f := range templateFindings {
		switch f.Severity {
		case report.SeverityHigh:
			data.HighCount++
		case report.SeverityMedium:
			data.MediumCount++
		case report.SeverityLow:
			data.LowCount++
		case report.SeverityInfo:
			data.InfoCount++
		}
	}
	data.TotalIssues = len(templateFindings)

	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	fmt.Printf("HTML Report saved to: %s\n", filename)
	return t.Execute(f, data)
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.UITitle}} - {{.Target}}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f4f4f9; }
        h1, h2, h3 { color: #2c3e50; }
        .header { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .dashboard { display: flex; gap: 20px; margin-bottom: 20px; align-items: stretch; }
        .summary-cards { flex: 2; display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
        .chart-container { flex: 1; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: center; align-items: center; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; display: flex; flex-direction: column; justify-content: center; }
        .card h3 { margin: 0; font-size: 2em; }
        .card p { margin: 5px 0 0; color: #666; }
        .high { color: #dc3545; border-top: 4px solid #dc3545; }
        .medium { color: #ffc107; border-top: 4px solid #ffc107; }
        .low { color: #0d6efd; border-top: 4px solid #0d6efd; }
        .info { color: #6c757d; border-top: 4px solid #6c757d; }
        .finding { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 15px; border-left: 5px solid #ccc; }
        .finding.HIGH { border-left-color: #dc3545; }
        .finding.MEDIUM { border-left-color: #ffc107; }
        .finding.LOW { border-left-color: #0d6efd; }
        .finding.INFO { border-left-color: #6c757d; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .severity-badge { padding: 5px 10px; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.8em; }
        .bg-HIGH { background-color: #dc3545; }
        .bg-MEDIUM { background-color: #ffc107; color: #000; }
        .bg-LOW { background-color: #0d6efd; }
        .bg-INFO { background-color: #6c757d; }
        code { background: #f8f9fa; padding: 2px 5px; border-radius: 3px; font-family: Consolas, Monaco, monospace; }
        .details { margin-top: 10px; }
        .label { font-weight: bold; color: #555; }
        .fix-box { background-color: #e8f5e9; padding: 15px; border-radius: 6px; border-left: 5px solid #4caf50; margin-top: 15px; }
        .fix-title { font-weight: bold; color: #2e7d32; display: block; margin-bottom: 5px; font-size: 1.05em; }
        .fix-content { color: #1b5e20; }
        .evidence-box { background-color: #fff3e0; padding: 15px; border-radius: 6px; border-left: 5px solid #ff9800; margin-top: 15px; }
        .evidence-title { font-weight: bold; color: #e65100; display: block; margin-bottom: 5px; font-size: 1.05em; }
        .evidence-content code { color: #bf360c; background-color: #fbe9e7; padding: 3px 6px; border-radius: 4px; }
        .affected-urls-box { background-color: #e3f2fd; padding: 15px; border-radius: 6px; border-left: 5px solid #2196f3; margin-top: 15px; }
        .affected-urls-title { font-weight: bold; color: #1565c0; display: block; margin-bottom: 5px; font-size: 1.05em; }
        .affected-urls-list { list-style-type: none; padding: 0; margin: 0; font-family: monospace; font-size: 0.9em; word-break: break-all; }
        .affected-urls-list li { padding: 2px 0; }
        .scope-container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .scope-list { max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 4px; border: 1px solid #eee; }
        .scope-list ul { list-style-type: none; padding: 0; margin: 0; }
        .scope-list li { padding: 5px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 0.9em; word-break: break-all; }
        .scope-list li:last-child { border-bottom: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.UITitle}}</h1>
        <p><strong>{{.UITarget}}:</strong> {{.Target}}</p>
        <p><strong>{{.UIScanTime}}:</strong> {{.ScanTime}}</p>
        <p><strong>{{.UIDuration}}:</strong> {{.Duration}}</p>
    </div>

    <div class="dashboard">
        <div class="summary-cards">
            <div class="card high"><h3>{{.HighCount}}</h3><p>{{.UIHigh}}</p></div>
            <div class="card medium"><h3>{{.MediumCount}}</h3><p>{{.UIMedium}}</p></div>
            <div class="card low"><h3>{{.LowCount}}</h3><p>{{.UILow}}</p></div>
            <div class="card info"><h3>{{.InfoCount}}</h3><p>{{.UIInfo}}</p></div>
        </div>
        <div class="chart-container">
            <canvas id="severityChart"></canvas>
        </div>
    </div>

    <div class="scope-container">
        <h3>{{.UICrawledScope}} ({{len .ScannedURLs}} URLs)</h3>
        <div class="scope-list">
            <ul>
                {{range .ScannedURLs}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>
    </div>

    <h2>{{.UIFindings}} ({{.TotalIssues}})</h2>
    {{range .Findings}}
    <div class="finding {{.Severity}}">
        <div class="finding-header">
            <h3>{{.Title}}</h3>
            <span class="severity-badge bg-{{.Severity}}">{{.Severity}}</span>
        </div>
        <div class="details">
            <p><span class="label">Category:</span> {{.Category}}</p>
            <p><span class="label">Description:</span> {{.Description}}</p>
            {{if .Evidence}}
            <div class="evidence-box">
                <span class="evidence-title">{{$.UIEvidence}}</span>
                <div class="evidence-content"><code>{{.Evidence}}</code></div>
            </div>
            {{end}}
            <div class="fix-box">
                <span class="fix-title">{{$.UIRecommendation}}</span>
                <div class="fix-content">{{.Fix}}</div>
            </div>
            {{if .AffectedURLs}}
            <div class="affected-urls-box">
                <span class="affected-urls-title">Affected URLs</span>
                <ul class="affected-urls-list">
                {{range .AffectedURLs}}
                    <li>{{.}}</li>
                {{end}}
                </ul>
            </div>
            {{end}}
            {{if .IsPotentiallyFalsePositive}}
            <p style="color: #e67e22;">{{$.UIManualVerification}}</p>
            {{end}}
        </div>
    </div>
    {{else}}
    <div class="finding">
        <p>{{.UINoVulns}}</p>
    </div>
    {{end}}

    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['{{.UIHigh}}', '{{.UIMedium}}', '{{.UILow}}', '{{.UIInfo}}'],
                datasets: [{
                    data: [{{.HighCount}}, {{.MediumCount}}, {{.LowCount}}, {{.InfoCount}}],
                    backgroundColor: ['#dc3545', '#ffc107', '#0d6efd', '#6c757d'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                    },
                    title: {
                        display: true,
                        text: '{{.UIChartTitle}}'
                    }
                }
            }
        });
    </script>
</body>
</html>
`
