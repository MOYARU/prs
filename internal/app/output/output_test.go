package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MOYARU/prs/internal/report"
)

func TestSaveJSONReportSummaryCounts(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir(tmp) error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	findings := []report.Finding{
		{ID: "A", Severity: report.SeverityHigh},
		{ID: "B", Severity: report.SeverityMedium},
		{ID: "C", Severity: report.SeverityMedium},
		{ID: "D", Severity: report.SeverityLow},
		{ID: "E", Severity: report.SeverityInfo},
	}

	start := time.Now().Add(-2 * time.Second)
	end := time.Now()
	if err := SaveJSONReport("https://example.com", []string{"https://example.com"}, findings, nil, start, end); err != nil {
		t.Fatalf("SaveJSONReport() error: %v", err)
	}

	files, err := filepath.Glob("prs_report_*.json")
	if err != nil {
		t.Fatalf("Glob() error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 report file, got %d: %v", len(files), files)
	}

	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	var doc struct {
		Summary struct {
			High   int `json:"high"`
			Medium int `json:"medium"`
			Low    int `json:"low"`
			Info   int `json:"info"`
			Total  int `json:"total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if doc.Summary.High != 1 || doc.Summary.Medium != 2 || doc.Summary.Low != 1 || doc.Summary.Info != 1 || doc.Summary.Total != 5 {
		t.Fatalf("unexpected summary: %+v", doc.Summary)
	}
}
