package report

import (
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/MOYARU/prs/internal/config"
)

var (
	reBearer    = regexp.MustCompile(`(?i)\b(bearer\s+)([a-z0-9\-\._~\+\/]+=*)`)
	reApiKeyKV  = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|token|secret|authorization)\s*[:=]\s*([^\s,;]+)`)
	reLongToken = regexp.MustCompile(`\b[a-zA-Z0-9_\-]{24,}\b`)
	customOnce  sync.Once
	customRes   []*regexp.Regexp
)

func SanitizeFinding(f Finding) Finding {
	f.Message = SanitizeText(f.Message)
	f.Evidence = SanitizeText(f.Evidence)
	f.Fix = SanitizeText(f.Fix)
	for i, u := range f.AffectedURLs {
		f.AffectedURLs[i] = SanitizeURL(u)
	}
	return f
}

func SanitizeText(s string) string {
	out := s
	out = reBearer.ReplaceAllString(out, "${1}<redacted>")
	out = reApiKeyKV.ReplaceAllString(out, "${1}=<redacted>")
	out = reLongToken.ReplaceAllStringFunc(out, func(tok string) string {
		if len(tok) <= 10 {
			return "<redacted>"
		}
		return tok[:4] + "...<redacted>..." + tok[len(tok)-4:]
	})
	for _, re := range customRegexes() {
		out = re.ReplaceAllString(out, "<redacted>")
	}
	return out
}

func customRegexes() []*regexp.Regexp {
	customOnce.Do(func() {
		for _, p := range config.LoadRedactionPatternsFromPRS() {
			re, err := regexp.Compile(p)
			if err == nil {
				customRes = append(customRes, re)
			}
		}
	})
	return customRes
}

func SanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return SanitizeText(raw)
	}

	q := u.Query()
	for k := range q {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "token") ||
			strings.Contains(kl, "key") ||
			strings.Contains(kl, "secret") ||
			strings.Contains(kl, "auth") ||
			strings.Contains(kl, "session") ||
			strings.Contains(kl, "pass") {
			q.Set(k, "<redacted>")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
