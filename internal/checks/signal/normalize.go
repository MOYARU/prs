package signal

import (
	"regexp"
	"strings"
)

var (
	reTimestamp = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b`)
	reUUID      = regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	reHexLong   = regexp.MustCompile(`\b[0-9a-f]{24,}\b`)
	reDigits    = regexp.MustCompile(`\b\d{2,}\b`)
	reSpace     = regexp.MustCompile(`\s+`)
)

// NormalizeForDiff removes highly dynamic tokens before similarity/diff checks
// to reduce false positives caused by timestamps, UUIDs, long IDs, and counters.
func NormalizeForDiff(s string) string {
	l := strings.ToLower(s)
	l = reTimestamp.ReplaceAllString(l, "<ts>")
	l = reUUID.ReplaceAllString(l, "<uuid>")
	l = reHexLong.ReplaceAllString(l, "<hex>")
	l = reDigits.ReplaceAllString(l, "<n>")
	l = reSpace.ReplaceAllString(strings.TrimSpace(l), " ")
	return l
}
