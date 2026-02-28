package engine

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DomainBoundaryTransport blocks requests outside the allowed root domain.
type DomainBoundaryTransport struct {
	Base              http.RoundTripper
	AllowedRootDomain string
}

func (t *DomainBoundaryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		return nil, fmt.Errorf("blocked request: empty host")
	}
	allowed := strings.ToLower(strings.TrimSpace(t.AllowedRootDomain))
	if allowed != "" {
		root, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			root = host
		}
		if root != allowed && host != allowed && !strings.HasSuffix(host, "."+allowed) {
			return nil, fmt.Errorf("blocked cross-domain request: %s (allowed root: %s)", host, allowed)
		}
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
