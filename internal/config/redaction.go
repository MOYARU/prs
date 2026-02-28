package config

import (
	"bufio"
	"os"
	"strings"
)

// LoadRedactionPatternsFromPRS reads ".prs.yaml" and returns regex strings under:
// redaction_patterns:
//   - '...'
func LoadRedactionPatternsFromPRS() []string {
	f, err := os.Open(".prs.yaml")
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []string
	inSection := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "redaction_patterns:") {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			p = strings.Trim(p, `"'`)
			if p != "" {
				patterns = append(patterns, p)
			}
			continue
		}
		// leave section if another top-level key starts
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "-") {
			inSection = false
		}
	}
	return patterns
}
