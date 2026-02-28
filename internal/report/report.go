package report

type Severity string
type Confidence string
type ValidationStatus string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"

	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"

	ValidationConfirmed ValidationStatus = "CONFIRMED"
	ValidationProbable  ValidationStatus = "PROBABLE"
)

type Finding struct {
	ID                         string           `json:"id"`
	Category                   string           `json:"category"`
	Severity                   Severity         `json:"severity"`
	Confidence                 Confidence       `json:"confidence"`
	Validation                 ValidationStatus `json:"validation,omitempty"`
	EvidenceQuality            int              `json:"evidence_quality,omitempty"`
	Title                      string           `json:"title"`
	Message                    string           `json:"message"`
	Evidence                   string           `json:"evidence"`
	Fix                        string           `json:"fix"`
	IsPotentiallyFalsePositive bool             `json:"is_potentially_false_positive"`
	AffectedURLs               []string         `json:"affected_urls,omitempty"`
}
