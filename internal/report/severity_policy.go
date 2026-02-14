package report

// severityOverrides provides a centralized place to tune risk classification
// without touching each checker implementation.
var severityOverrides = map[string]Severity{
	"PII_LEAKAGE_EMAIL":                       SeverityLow,
	"RETRY_AFTER_HEADER_MISSING":              SeverityInfo,
	"X_RATELIMIT_HEADERS_MISSING":             SeverityLow,
	"SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED": SeverityInfo,
	"IDOR_POSSIBLE":                           SeverityMedium,
	"IDOR_RESOURCE_GUESSING":                  SeverityLow,
	"INFORMATION_LEAKAGE_X_POWERED_BY":        SeverityInfo,
	"INFORMATION_LEAKAGE_SERVER_HEADER":       SeverityInfo,
	"INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE": SeverityLow,
	"SERVER_HEADER_EXPOSED":                   SeverityInfo,
	"X_POWERED_BY_EXPOSED":                    SeverityInfo,
}

func ApplySeverityOverride(f Finding) Finding {
	if sev, ok := severityOverrides[f.ID]; ok {
		f.Severity = sev
	}
	return f
}
