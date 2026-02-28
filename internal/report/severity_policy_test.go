package report

import "testing"

func TestApplySeverityOverride(t *testing.T) {
	tests := []struct {
		name string
		in   Finding
		want Severity
	}{
		{
			name: "override to info",
			in:   Finding{ID: "RETRY_AFTER_HEADER_MISSING", Severity: SeverityHigh},
			want: SeverityInfo,
		},
		{
			name: "override to low",
			in:   Finding{ID: "PII_LEAKAGE_EMAIL", Severity: SeverityHigh},
			want: SeverityLow,
		},
		{
			name: "no override keeps original",
			in:   Finding{ID: "UNKNOWN_ID", Severity: SeverityMedium},
			want: SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplySeverityOverride(tt.in)
			if got.Severity != tt.want {
				t.Fatalf("severity mismatch: got=%s want=%s", got.Severity, tt.want)
			}
		})
	}
}
