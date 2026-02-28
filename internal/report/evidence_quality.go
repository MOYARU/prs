package report

import "strings"

// ScoreEvidenceQuality computes a lightweight evidence quality score in range [0,100].
func ScoreEvidenceQuality(f Finding) int {
	score := 30

	switch f.Confidence {
	case ConfidenceHigh:
		score += 35
	case ConfidenceMedium:
		score += 22
	case ConfidenceLow:
		score += 10
	}

	switch f.Validation {
	case ValidationConfirmed:
		score += 20
	case ValidationProbable:
		score += 12
	}

	eLen := len(strings.TrimSpace(f.Evidence))
	switch {
	case eLen >= 160:
		score += 15
	case eLen >= 80:
		score += 10
	case eLen >= 30:
		score += 5
	}

	if f.IsPotentiallyFalsePositive {
		score -= 15
	}

	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
