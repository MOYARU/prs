package output

import (
	"fmt"
	"html/template"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MOYARU/prs/internal/checks/scanner"
	"github.com/MOYARU/prs/internal/config"
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
	UIValidation         string
	UIManualVerification string
	UINoVulns            string
	CheckStats           map[string]scanner.CheckStat
	RiskConfidenceRows   []RiskConfidenceRow
	CategoryRows         []CategorySummaryRow
	URLRows              []URLSeverityRow
	AttackSurface        AttackSurfaceData
	TopRemediations      []RemediationPriorityRow
}

type RiskConfidenceRow struct {
	Confidence string
	High       int
	Medium     int
	Low        int
	Info       int
	Total      int
}

type CategorySummaryRow struct {
	Category string
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

type URLSeverityRow struct {
	URL    string
	High   int
	Medium int
	Low    int
	Info   int
	Total  int
}

type AttackSurfaceData struct {
	TotalURLs        int
	DynamicURLs      int
	APIEndpoints     int
	AuthEndpoints    int
	AdminEndpoints   int
	UploadEndpoints  int
	DebugEndpoints   int
	GraphQLEndpoints int
	TopParams        []NamedCount
	HighRiskRoutes   []RouteRiskRow
}

type NamedCount struct {
	Name  string
	Count int
}

type RouteRiskRow struct {
	URL     string
	Score   int
	Reasons string
}

type RemediationPriorityRow struct {
	Key         string
	Score       int
	Count       int
	High        int
	Medium      int
	Low         int
	Info        int
	SampleTitle string
	Action      string
}

// SaveHTML report generates and saves an HTML report to a file.
func SaveHTMLReport(target string, scannedURLs []string, findings []report.Finding, checkStats map[string]scanner.CheckStat, startTime, endTime time.Time) error {
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
		UIValidation:         msges.GetUIMessage("ConsoleValidationLabel"),
		UIManualVerification: msges.GetUIMessage("UIManualVerification"),
		UINoVulns:            msges.GetUIMessage("ConsoleNoIssues"),
		CheckStats:           checkStats,
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
	data.RiskConfidenceRows = buildRiskConfidenceRows(findings)
	data.CategoryRows = buildCategoryRows(findings)
	data.URLRows = buildURLSeverityRows(scannedURLs, findings)
	data.AttackSurface = buildAttackSurfaceData(scannedURLs, findings)
	policy := config.LoadScanPolicyFromPRS()
	limit := policy.TopRemediationLimit
	if limit <= 0 {
		limit = 10
	}
	data.TopRemediations = buildTopRemediationRows(findings, limit)

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
        :root {
            --bg: #ffffff;
            --surface: #ffffff;
            --surface-soft: #fbfcfe;
            --text: #16324d;
            --muted: #5b738c;
            --line: #d9e1ea;
            --high: #d64545;
            --medium: #e6a900;
            --low: #1d6eea;
            --info: #6f7f8f;
            --radius-lg: 16px;
            --radius-md: 12px;
            --shadow-1: 0 8px 20px rgba(16, 53, 88, 0.08);
            --shadow-2: 0 2px 8px rgba(16, 53, 88, 0.06);
        }
        * { box-sizing: border-box; }
        body {
            font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: var(--text);
            margin: 0;
            padding: 28px 16px 40px;
            background: var(--bg);
        }
        .page {
            max-width: 1240px;
            margin: 0 auto;
        }
        h1, h2, h3 { margin: 0; color: #0b3d6e; }
        p { margin: 0.25rem 0; }
        .surface {
            background: var(--surface);
            border: 1px solid rgba(36, 93, 148, 0.08);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-1);
        }
        .header {
            padding: 28px 28px 22px;
            margin-bottom: 20px;
            border: 1px solid var(--line);
        }
        .header-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 8px 16px;
            margin-top: 12px;
            color: var(--muted);
        }
        .dashboard {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
            align-items: stretch;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 14px;
        }
        .chart-container {
            padding: 18px;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .card {
            background: linear-gradient(180deg, #ffffff, var(--surface-soft));
            border: 1px solid var(--line);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-2);
            padding: 20px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: 4px;
        }
        .card h3 { margin: 0; font-size: 2rem; line-height: 1; }
        .card p { margin: 0; color: var(--muted); font-weight: 600; letter-spacing: .01em; }
        .high { color: var(--high); border-top: 4px solid var(--high); }
        .medium { color: var(--medium); border-top: 4px solid var(--medium); }
        .low { color: var(--low); border-top: 4px solid var(--low); }
        .info { color: var(--info); border-top: 4px solid var(--info); }
        .scope-container, .findings-wrap {
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--line);
        }
        .finding {
            background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%);
            padding: 18px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-2);
            margin-bottom: 14px;
            border: 1px solid var(--line);
            border-left: 6px solid #a7b7c7;
        }
        .finding.HIGH { border-left-color: var(--high); }
        .finding.MEDIUM { border-left-color: var(--medium); }
        .finding.LOW { border-left-color: var(--low); }
        .finding.INFO { border-left-color: var(--info); }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .severity-badge {
            padding: 5px 10px;
            border-radius: 999px;
            color: #fff;
            font-weight: 700;
            font-size: 0.76rem;
            letter-spacing: .03em;
            border: 1px solid rgba(255,255,255,.35);
        }
        .bg-HIGH { background-color: var(--high); }
        .bg-MEDIUM { background-color: var(--medium); color: #1d1d1d; }
        .bg-LOW { background-color: var(--low); }
        .bg-INFO { background-color: var(--info); }
        code {
            background: #f2f8ff;
            padding: 2px 6px;
            border-radius: 6px;
            border: 1px solid var(--line);
            font-family: Consolas, Monaco, monospace;
        }
        .details { margin-top: 10px; }
        .label { font-weight: 700; color: #35506c; }
        .fix-box, .evidence-box, .affected-urls-box {
            padding: 14px;
            border-radius: 10px;
            margin-top: 14px;
            border: 1px solid var(--line);
            background: #f7fbff;
        }
        .fix-box { border-left: 5px solid #3f9f5f; background: #edf9f0; }
        .fix-title { font-weight: 700; color: #2d7f4a; display: block; margin-bottom: 6px; font-size: 1.02rem; }
        .fix-content { color: #245f38; }
        .evidence-box { border-left: 5px solid #d38a2c; background: #fff8ec; }
        .evidence-title { font-weight: 700; color: #9b5f13; display: block; margin-bottom: 6px; font-size: 1.02rem; }
        .evidence-content code { color: #7f4b0c; background-color: #fff3dc; }
        .affected-urls-box { border-left: 5px solid #3386e0; background: #edf5ff; }
        .affected-urls-title { font-weight: 700; color: #205a9a; display: block; margin-bottom: 5px; font-size: 1.02rem; }
        .affected-urls-list { list-style-type: none; padding: 0; margin: 0; font-family: monospace; font-size: 0.9em; word-break: break-all; }
        .affected-urls-list li { padding: 2px 0; }
        .scope-list { max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 4px; border: 1px solid #eee; }
        .scope-list ul { list-style-type: none; padding: 0; margin: 0; }
        .scope-list li { padding: 5px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 0.9em; word-break: break-all; }
        .scope-list li:last-child { border-bottom: none; }
        details.collapse { margin-top: 8px; }
        details.collapse summary { cursor: pointer; list-style: none; font-weight: 700; color: #1f4e80; }
        details.collapse summary::-webkit-details-marker { display: none; }
        details.collapse summary::before { content: ">"; display: inline-block; margin-right: 8px; transition: transform 0.15s ease-in-out; font-weight: 700; }
        details.collapse[open] summary::before { transform: rotate(90deg); }
        .contents {
            padding: 16px 20px;
            margin-bottom: 20px;
            border: 1px solid var(--line);
            border-radius: var(--radius-md);
            background: var(--surface-soft);
        }
        .contents a {
            color: #1c5f9e;
            text-decoration: none;
            border-bottom: 1px dotted #1c5f9e;
            margin-right: 14px;
        }
        .summary-table-wrap {
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--line);
            border-radius: var(--radius-md);
            background: var(--surface);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: .95rem;
        }
        th, td {
            border-bottom: 1px solid #e7edf4;
            padding: 8px 10px;
            text-align: right;
        }
        th:first-child, td:first-child {
            text-align: left;
        }
        thead th {
            background: #f5f9fd;
            color: #285b8a;
            font-weight: 700;
        }
        .finding-controls {
            display: flex;
            flex-wrap: wrap;
            gap: 8px 10px;
            margin: 12px 0 18px;
            align-items: center;
        }
        .chip {
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: 6px 10px;
            background: #f7fafc;
            font-size: .85rem;
        }
        .search {
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 8px 10px;
            min-width: 260px;
        }
        .hidden-by-filter { display: none; }
        .finding-count-hint {
            color: var(--muted);
            font-size: .9rem;
            margin-left: auto;
        }
        .table-controls {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
            margin: 8px 0 10px;
        }
        .table-note {
            color: var(--muted);
            font-size: .88rem;
        }
        th.sortable {
            cursor: pointer;
            user-select: none;
            position: relative;
        }
        th.sortable::after {
            content: " <> ";
            font-weight: 400;
            color: #7a8ea2;
        }
        th.sortable.asc::after {
            content: " ^ ";
            color: #2c5f91;
        }
        th.sortable.desc::after {
            content: " v ";
            color: #2c5f91;
        }
        @media (max-width: 1024px) {
            .dashboard { grid-template-columns: 1fr; }
        }
        @media (max-width: 640px) {
            .summary-cards { grid-template-columns: 1fr 1fr; }
            .header { padding: 20px 16px 16px; }
            .scope-container, .findings-wrap { padding: 16px; }
        }
    </style>
</head>
<body>
    <div class="page">
    <div class="header surface">
        <h1>{{.UITitle}}</h1>
        <div class="header-meta">
            <p><strong>{{.UITarget}}:</strong> {{.Target}}</p>
            <p><strong>{{.UIScanTime}}:</strong> {{.ScanTime}}</p>
            <p><strong>{{.UIDuration}}:</strong> {{.Duration}}</p>
        </div>
    </div>

    <div class="contents">
        <strong>Contents:</strong>
        <a href="#summary">Summary</a>
        <a href="#risk-confidence">Risk/Confidence</a>
        <a href="#category-summary">Category Summary</a>
        <a href="#url-summary">URL Summary</a>
        <a href="#top-remediation">Top Remediation</a>
        <a href="#attack-surface">Attack Surface</a>
        <a href="#scope">Scope</a>
        <a href="#findings">Findings</a>
    </div>

    <div class="dashboard" id="summary">
        <div class="summary-cards">
            <div class="card high"><h3>{{.HighCount}}</h3><p>{{.UIHigh}}</p></div>
            <div class="card medium"><h3>{{.MediumCount}}</h3><p>{{.UIMedium}}</p></div>
            <div class="card low"><h3>{{.LowCount}}</h3><p>{{.UILow}}</p></div>
            <div class="card info"><h3>{{.InfoCount}}</h3><p>{{.UIInfo}}</p></div>
        </div>
        <div class="chart-container surface">
            <canvas id="severityChart"></canvas>
        </div>
    </div>

    <div class="summary-table-wrap" id="risk-confidence">
        <h3>Risk / Confidence Matrix</h3>
        <table>
            <thead>
                <tr>
                    <th>Confidence</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Info</th>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
                {{range .RiskConfidenceRows}}
                <tr>
                    <td>{{.Confidence}}</td>
                    <td>{{.High}}</td>
                    <td>{{.Medium}}</td>
                    <td>{{.Low}}</td>
                    <td>{{.Info}}</td>
                    <td>{{.Total}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="summary-table-wrap" id="category-summary">
        <h3>Category Summary</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Info</th>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
                {{range .CategoryRows}}
                <tr>
                    <td>{{.Category}}</td>
                    <td>{{.High}}</td>
                    <td>{{.Medium}}</td>
                    <td>{{.Low}}</td>
                    <td>{{.Info}}</td>
                    <td>{{.Total}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="summary-table-wrap" id="url-summary">
        <h3>URL Severity Summary</h3>
        <div class="table-controls">
            <label class="chip"><input type="checkbox" id="urlHighOnly"> Show only URLs with HIGH</label>
            <span class="table-note"><span id="urlVisibleCount">{{len .URLRows}}</span> URLs shown</span>
        </div>
        <table id="urlSummaryTable">
            <thead>
                <tr>
                    <th class="sortable" data-col="url" data-type="string">URL</th>
                    <th class="sortable" data-col="high" data-type="number">High</th>
                    <th class="sortable" data-col="medium" data-type="number">Medium</th>
                    <th class="sortable" data-col="low" data-type="number">Low</th>
                    <th class="sortable" data-col="info" data-type="number">Info</th>
                    <th class="sortable" data-col="total" data-type="number">Total</th>
                </tr>
            </thead>
            <tbody>
                {{range .URLRows}}
                <tr data-url="{{.URL}}" data-high="{{.High}}" data-medium="{{.Medium}}" data-low="{{.Low}}" data-info="{{.Info}}" data-total="{{.Total}}">
                    <td><code>{{.URL}}</code></td>
                    <td>{{.High}}</td>
                    <td>{{.Medium}}</td>
                    <td>{{.Low}}</td>
                    <td>{{.Info}}</td>
                    <td>{{.Total}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="summary-table-wrap" id="top-remediation">
        <h3>Top Remediation Priorities</h3>
        <table>
            <thead>
                <tr>
                    <th>Rule</th>
                    <th>Score</th>
                    <th>Count</th>
                    <th>H</th>
                    <th>M</th>
                    <th>L</th>
                    <th>I</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {{range .TopRemediations}}
                <tr>
                    <td><code>{{.Key}}</code><br><span class="table-note">{{.SampleTitle}}</span></td>
                    <td>{{.Score}}</td>
                    <td>{{.Count}}</td>
                    <td>{{.High}}</td>
                    <td>{{.Medium}}</td>
                    <td>{{.Low}}</td>
                    <td>{{.Info}}</td>
                    <td>{{.Action}}</td>
                </tr>
                {{else}}
                <tr><td colspan="8">No remediation candidates.</td></tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="summary-table-wrap" id="attack-surface">
        <h3>Attack Surface Intelligence</h3>
        <div class="dashboard" style="margin-bottom: 12px;">
            <div class="summary-cards">
                <div class="card"><h3>{{.AttackSurface.TotalURLs}}</h3><p>Total URLs</p></div>
                <div class="card"><h3>{{.AttackSurface.DynamicURLs}}</h3><p>Dynamic URLs</p></div>
                <div class="card"><h3>{{.AttackSurface.APIEndpoints}}</h3><p>API Endpoints</p></div>
                <div class="card"><h3>{{.AttackSurface.DebugEndpoints}}</h3><p>Debug/Meta Endpoints</p></div>
            </div>
            <div class="summary-cards">
                <div class="card"><h3>{{.AttackSurface.AuthEndpoints}}</h3><p>Auth Endpoints</p></div>
                <div class="card"><h3>{{.AttackSurface.AdminEndpoints}}</h3><p>Admin Endpoints</p></div>
                <div class="card"><h3>{{.AttackSurface.UploadEndpoints}}</h3><p>Upload/File Endpoints</p></div>
                <div class="card"><h3>{{.AttackSurface.GraphQLEndpoints}}</h3><p>GraphQL Endpoints</p></div>
            </div>
        </div>

        <h4 style="margin-top: 8px;">Top Risky Parameters</h4>
        <table>
            <thead>
                <tr>
                    <th>Parameter</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                {{range .AttackSurface.TopParams}}
                <tr>
                    <td><code>{{.Name}}</code></td>
                    <td>{{.Count}}</td>
                </tr>
                {{else}}
                <tr><td colspan="2">No query parameters observed.</td></tr>
                {{end}}
            </tbody>
        </table>

        <h4 style="margin-top: 16px;">High-Risk Routes (Score-based)</h4>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Score</th>
                    <th>Reasons</th>
                </tr>
            </thead>
            <tbody>
                {{range .AttackSurface.HighRiskRoutes}}
                <tr>
                    <td><code>{{.URL}}</code></td>
                    <td>{{.Score}}</td>
                    <td>{{.Reasons}}</td>
                </tr>
                {{else}}
                <tr><td colspan="3">No high-risk routes identified with current heuristics.</td></tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="scope-container surface" id="scope">
        <h3>{{.UICrawledScope}} ({{len .ScannedURLs}} URLs)</h3>
        <details class="collapse">
            <summary>URL List</summary>
            <div class="scope-list">
                <ul>
                    {{range .ScannedURLs}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
            </div>
        </details>
    </div>

    <div class="findings-wrap surface" id="findings">
    <h2>{{.UIFindings}} ({{.TotalIssues}})</h2>
    <div class="finding-controls">
        <input id="searchInput" class="search" type="text" placeholder="Filter by title/category/evidence...">
        <label class="chip"><input type="checkbox" class="sev-filter" value="HIGH" checked> HIGH</label>
        <label class="chip"><input type="checkbox" class="sev-filter" value="MEDIUM" checked> MEDIUM</label>
        <label class="chip"><input type="checkbox" class="sev-filter" value="LOW" checked> LOW</label>
        <label class="chip"><input type="checkbox" class="sev-filter" value="INFO" checked> INFO</label>
        <label class="chip"><input type="checkbox" id="manualOnly"> Manual Review</label>
        <span class="finding-count-hint"><span id="visibleCount">{{.TotalIssues}}</span> visible</span>
    </div>
    {{range .Findings}}
    <div class="finding {{.Severity}}" data-severity="{{.Severity}}" data-manual="{{if .IsPotentiallyFalsePositive}}1{{else}}0{{end}}" data-search="{{.Title}} {{.Category}} {{.Description}} {{.Evidence}}">
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
            {{if .Validation}}
            <p><span class="label">{{$.UIValidation}}:</span> <code>{{.Validation}}</code></p>
            {{end}}
            <div class="fix-box">
                <span class="fix-title">{{$.UIRecommendation}}</span>
                <div class="fix-content">{{.Fix}}</div>
            </div>
            {{if .AffectedURLs}}
            <div class="affected-urls-box">
                <details class="collapse">
                    <summary class="affected-urls-title">Affected URLs ({{len .AffectedURLs}})</summary>
                    <ul class="affected-urls-list">
                    {{range .AffectedURLs}}
                        <li>{{.}}</li>
                    {{end}}
                    </ul>
                </details>
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
    </div>
    </div>

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

        const searchInput = document.getElementById('searchInput');
        const severityFilters = Array.from(document.querySelectorAll('.sev-filter'));
        const manualOnly = document.getElementById('manualOnly');
        const cards = Array.from(document.querySelectorAll('.finding[data-severity]'));
        const visibleCount = document.getElementById('visibleCount');

        function applyFilters() {
            const enabledSev = new Set(
                severityFilters.filter(f => f.checked).map(f => f.value)
            );
            const q = (searchInput.value || '').toLowerCase().trim();
            const manual = manualOnly.checked;
            let count = 0;

            cards.forEach(card => {
                const sev = card.dataset.severity;
                const isManual = card.dataset.manual === '1';
                const text = (card.dataset.search || '').toLowerCase();
                const passSev = enabledSev.has(sev);
                const passManual = !manual || isManual;
                const passSearch = q === '' || text.includes(q);
                const show = passSev && passManual && passSearch;
                card.classList.toggle('hidden-by-filter', !show);
                if (show) count++;
            });

            visibleCount.textContent = String(count);
        }

        searchInput.addEventListener('input', applyFilters);
        severityFilters.forEach(f => f.addEventListener('change', applyFilters));
        manualOnly.addEventListener('change', applyFilters);

        const urlTable = document.getElementById('urlSummaryTable');
        const urlBody = urlTable ? urlTable.querySelector('tbody') : null;
        const urlRows = urlBody ? Array.from(urlBody.querySelectorAll('tr')) : [];
        const urlHeaders = urlTable ? Array.from(urlTable.querySelectorAll('th.sortable')) : [];
        const urlHighOnly = document.getElementById('urlHighOnly');
        const urlVisibleCount = document.getElementById('urlVisibleCount');
        let urlSort = { col: 'total', dir: 'desc', type: 'number' };

        function applyURLFiltersAndSort() {
            if (!urlRows.length) return;

            const onlyHigh = urlHighOnly && urlHighOnly.checked;
            const sorted = [...urlRows].sort((a, b) => {
                const col = urlSort.col;
                const type = urlSort.type;
                let av = a.dataset[col] || '';
                let bv = b.dataset[col] || '';
                if (type === 'number') {
                    av = Number(av);
                    bv = Number(bv);
                    if (av === bv) {
                        const au = a.dataset.url || '';
                        const bu = b.dataset.url || '';
                        return au.localeCompare(bu);
                    }
                } else {
                    av = String(av).toLowerCase();
                    bv = String(bv).toLowerCase();
                }
                if (av < bv) return urlSort.dir === 'asc' ? -1 : 1;
                if (av > bv) return urlSort.dir === 'asc' ? 1 : -1;
                return 0;
            });

            let visible = 0;
            sorted.forEach(row => {
                const high = Number(row.dataset.high || '0');
                const show = !onlyHigh || high > 0;
                row.style.display = show ? '' : 'none';
                if (show) visible++;
                urlBody.appendChild(row);
            });
            if (urlVisibleCount) urlVisibleCount.textContent = String(visible);
        }

        urlHeaders.forEach(h => {
            h.addEventListener('click', () => {
                const col = h.dataset.col;
                const type = h.dataset.type || 'string';
                if (urlSort.col === col) {
                    urlSort.dir = urlSort.dir === 'asc' ? 'desc' : 'asc';
                } else {
                    urlSort = { col, dir: type === 'number' ? 'desc' : 'asc', type };
                }

                urlHeaders.forEach(x => {
                    x.classList.remove('asc', 'desc');
                    if (x.dataset.col === urlSort.col) {
                        x.classList.add(urlSort.dir);
                    }
                });

                applyURLFiltersAndSort();
            });
        });

        if (urlHighOnly) {
            urlHighOnly.addEventListener('change', applyURLFiltersAndSort);
        }
        urlHeaders.forEach(x => {
            if (x.dataset.col === urlSort.col) x.classList.add(urlSort.dir);
        });
        applyURLFiltersAndSort();
    </script>
</body>
</html>
`

func buildRiskConfidenceRows(findings []report.Finding) []RiskConfidenceRow {
	type acc struct {
		high   int
		medium int
		low    int
		info   int
		total  int
	}
	order := []string{"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	bucket := make(map[string]*acc, len(order))
	for _, label := range order {
		bucket[label] = &acc{}
	}

	for _, f := range findings {
		conf := string(f.Confidence)
		if conf == "" {
			conf = "UNKNOWN"
		}
		if _, ok := bucket[conf]; !ok {
			bucket[conf] = &acc{}
			order = append(order, conf)
		}
		row := bucket[conf]
		switch f.Severity {
		case report.SeverityHigh:
			row.high++
		case report.SeverityMedium:
			row.medium++
		case report.SeverityLow:
			row.low++
		default:
			row.info++
		}
		row.total++
	}

	out := make([]RiskConfidenceRow, 0, len(order))
	for _, conf := range order {
		v := bucket[conf]
		if v == nil {
			continue
		}
		out = append(out, RiskConfidenceRow{
			Confidence: conf,
			High:       v.high,
			Medium:     v.medium,
			Low:        v.low,
			Info:       v.info,
			Total:      v.total,
		})
	}
	return out
}

func buildCategoryRows(findings []report.Finding) []CategorySummaryRow {
	type acc struct {
		high   int
		medium int
		low    int
		info   int
		total  int
	}
	byCategory := map[string]*acc{}
	for _, f := range findings {
		category := f.Category
		if category == "" {
			category = "Uncategorized"
		}
		if _, ok := byCategory[category]; !ok {
			byCategory[category] = &acc{}
		}
		row := byCategory[category]
		switch f.Severity {
		case report.SeverityHigh:
			row.high++
		case report.SeverityMedium:
			row.medium++
		case report.SeverityLow:
			row.low++
		default:
			row.info++
		}
		row.total++
	}

	rows := make([]CategorySummaryRow, 0, len(byCategory))
	for category, v := range byCategory {
		rows = append(rows, CategorySummaryRow{
			Category: category,
			High:     v.high,
			Medium:   v.medium,
			Low:      v.low,
			Info:     v.info,
			Total:    v.total,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total == rows[j].Total {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Total > rows[j].Total
	})
	return rows
}

func buildURLSeverityRows(scannedURLs []string, findings []report.Finding) []URLSeverityRow {
	type acc struct {
		high   int
		medium int
		low    int
		info   int
		total  int
	}

	byURL := make(map[string]*acc, len(scannedURLs))
	for _, u := range scannedURLs {
		if u == "" {
			continue
		}
		if _, ok := byURL[u]; !ok {
			byURL[u] = &acc{}
		}
	}

	for _, f := range findings {
		if len(f.AffectedURLs) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(f.AffectedURLs))
		for _, u := range f.AffectedURLs {
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			if _, ok := byURL[u]; !ok {
				byURL[u] = &acc{}
			}
			row := byURL[u]
			switch f.Severity {
			case report.SeverityHigh:
				row.high++
			case report.SeverityMedium:
				row.medium++
			case report.SeverityLow:
				row.low++
			default:
				row.info++
			}
			row.total++
		}
	}

	rows := make([]URLSeverityRow, 0, len(byURL))
	for u, v := range byURL {
		rows = append(rows, URLSeverityRow{
			URL:    u,
			High:   v.high,
			Medium: v.medium,
			Low:    v.low,
			Info:   v.info,
			Total:  v.total,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total == rows[j].Total {
			if rows[i].High == rows[j].High {
				return rows[i].URL < rows[j].URL
			}
			return rows[i].High > rows[j].High
		}
		return rows[i].Total > rows[j].Total
	})

	return rows
}

type routeRiskInfo struct {
	score   int
	reasons map[string]struct{}
}

func buildAttackSurfaceData(scannedURLs []string, findings []report.Finding) AttackSurfaceData {
	data := AttackSurfaceData{
		TotalURLs: len(scannedURLs),
	}

	riskyParamCounts := map[string]int{}
	routeRisk := map[string]*routeRiskInfo{}

	addRouteRisk := func(rawURL, reason string, score int) {
		if rawURL == "" || score <= 0 {
			return
		}
		if _, ok := routeRisk[rawURL]; !ok {
			routeRisk[rawURL] = &routeRiskInfo{reasons: map[string]struct{}{}}
		}
		routeRisk[rawURL].score += score
		routeRisk[rawURL].reasons[reason] = struct{}{}
	}

	for _, raw := range scannedURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		path := strings.ToLower(u.Path)
		if len(u.Query()) > 0 {
			data.DynamicURLs++
		}

		if strings.Contains(path, "/api") {
			data.APIEndpoints++
			addRouteRisk(raw, "API route", 1)
		}
		if strings.Contains(path, "graphql") {
			data.GraphQLEndpoints++
			addRouteRisk(raw, "GraphQL route", 2)
		}
		if strings.Contains(path, "login") || strings.Contains(path, "signin") || strings.Contains(path, "auth") || strings.Contains(path, "session") {
			data.AuthEndpoints++
			addRouteRisk(raw, "Auth/session route", 2)
		}
		if strings.Contains(path, "admin") || strings.Contains(path, "manage") || strings.Contains(path, "dashboard") || strings.Contains(path, "backoffice") {
			data.AdminEndpoints++
			addRouteRisk(raw, "Admin route", 3)
		}
		if strings.Contains(path, "upload") || strings.Contains(path, "file") || strings.Contains(path, "import") {
			data.UploadEndpoints++
			addRouteRisk(raw, "File handling route", 2)
		}
		if strings.Contains(path, "debug") || strings.Contains(path, "actuator") || strings.Contains(path, "swagger") || strings.Contains(path, ".well-known") {
			data.DebugEndpoints++
			addRouteRisk(raw, "Debug/meta route", 3)
		}

		for k := range u.Query() {
			p := strings.ToLower(strings.TrimSpace(k))
			if p == "" {
				continue
			}
			if isRiskyParamName(p) {
				riskyParamCounts[p]++
				addRouteRisk(raw, "Risky parameter: "+p, 1)
			}
		}
	}

	for _, f := range findings {
		impact := 0
		switch f.Severity {
		case report.SeverityHigh:
			impact = 4
		case report.SeverityMedium:
			impact = 2
		case report.SeverityLow:
			impact = 1
		}
		if impact == 0 || len(f.AffectedURLs) == 0 {
			continue
		}
		seen := map[string]struct{}{}
		for _, u := range f.AffectedURLs {
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			addRouteRisk(u, "Observed finding: "+string(f.Severity), impact)
		}
	}

	data.TopParams = buildTopNamedCounts(riskyParamCounts, 10)
	data.HighRiskRoutes = buildTopRouteRisks(routeRisk, 10, 4)
	return data
}

func isRiskyParamName(name string) bool {
	risky := []string{
		"id", "user", "uid", "account", "token", "key", "session",
		"redirect", "url", "next", "return", "callback", "file", "path",
		"dest", "target", "cmd", "query", "search",
	}
	for _, k := range risky {
		if name == k || strings.Contains(name, k) {
			return true
		}
	}
	return false
}

func buildTopNamedCounts(m map[string]int, max int) []NamedCount {
	rows := make([]NamedCount, 0, len(m))
	for k, v := range m {
		rows = append(rows, NamedCount{Name: k, Count: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Count > rows[j].Count
	})
	if max > 0 && len(rows) > max {
		rows = rows[:max]
	}
	return rows
}

func buildTopRouteRisks(m map[string]*routeRiskInfo, max int, minScore int) []RouteRiskRow {
	rows := make([]RouteRiskRow, 0, len(m))
	for u, v := range m {
		if v == nil || v.score < minScore {
			continue
		}
		reasons := make([]string, 0, len(v.reasons))
		for r := range v.reasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		rows = append(rows, RouteRiskRow{
			URL:     u,
			Score:   v.score,
			Reasons: strings.Join(reasons, ", "),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			return rows[i].URL < rows[j].URL
		}
		return rows[i].Score > rows[j].Score
	})
	if max > 0 && len(rows) > max {
		rows = rows[:max]
	}
	return rows
}

func buildTopRemediationRows(findings []report.Finding, limit int) []RemediationPriorityRow {
	type agg struct {
		score       int
		count       int
		high        int
		medium      int
		low         int
		info        int
		sampleTitle string
		action      string
	}

	byID := map[string]*agg{}
	for _, f := range findings {
		key := strings.TrimSpace(f.ID)
		if key == "" {
			key = "UNSPECIFIED_RULE"
		}
		if _, ok := byID[key]; !ok {
			byID[key] = &agg{
				sampleTitle: strings.TrimSpace(f.Title),
				action:      strings.TrimSpace(f.Fix),
			}
		}
		a := byID[key]
		a.count++
		switch f.Severity {
		case report.SeverityHigh:
			a.high++
			a.score += 8
		case report.SeverityMedium:
			a.medium++
			a.score += 5
		case report.SeverityLow:
			a.low++
			a.score += 2
		default:
			a.info++
			a.score += 1
		}
		if a.sampleTitle == "" && strings.TrimSpace(f.Title) != "" {
			a.sampleTitle = strings.TrimSpace(f.Title)
		}
		if a.action == "" && strings.TrimSpace(f.Fix) != "" {
			a.action = strings.TrimSpace(f.Fix)
		}
	}

	rows := make([]RemediationPriorityRow, 0, len(byID))
	for key, a := range byID {
		rows = append(rows, RemediationPriorityRow{
			Key:         key,
			Score:       a.score,
			Count:       a.count,
			High:        a.high,
			Medium:      a.medium,
			Low:         a.low,
			Info:        a.info,
			SampleTitle: a.sampleTitle,
			Action:      a.action,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			if rows[i].Count == rows[j].Count {
				return rows[i].Key < rows[j].Key
			}
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Score > rows[j].Score
	})

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}
