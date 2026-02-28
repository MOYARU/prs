package engine

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	appver "github.com/MOYARU/prs/internal/version"
)

type FetchResult struct {
	InitialURL        *url.URL
	FinalURL          *url.URL
	Response          *http.Response
	RedirectTarget    *url.URL
	Redirected        bool
	RedirectedToHTTPS bool
}

func Fetch(target string) (*FetchResult, error) {
	initialURL, err := normalizeTarget(target)
	if err != nil {
		return nil, err
	}

	resp, err := fetchOnce(initialURL.String(), false, nil)
	if err != nil {
		return nil, err
	}

	result := &FetchResult{
		InitialURL: initialURL,
		Response:   resp,
	}

	if isRedirect(resp.StatusCode) {
		location := resp.Header.Get("Location")
		if location == "" {
			resp.Body.Close()
			return nil, fmt.Errorf("redirect response missing Location header")
		}

		redirectURL, err := resolveURL(initialURL, location)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to resolve redirect URL: %w", err)
		}

		resp.Body.Close()

		finalResp, err := fetchOnce(redirectURL.String(), true, nil) // Pass nil for default TLS config
		if err != nil {
			return nil, err
		}

		result.Response = finalResp
		result.FinalURL = finalResp.Request.URL
		result.Redirected = true
		result.RedirectTarget = redirectURL
		result.RedirectedToHTTPS = redirectURL.Scheme == "https"
		return result, nil
	}

	result.FinalURL = resp.Request.URL
	return result, nil
}

type DelayedTransport struct {
	Transport http.RoundTripper
	Delay     time.Duration
}

func (t *DelayedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Delay > 0 {
		time.Sleep(t.Delay)
	}
	if t.Transport == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.Transport.RoundTrip(req)
}

func fetchOnce(target string, allowRedirect bool, tlsConfig *tls.Config) (*http.Response, error) {
	client := NewHTTPClient(allowRedirect, tlsConfig)

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", appver.ScannerUserAgent())

	return client.Do(req)
}

func normalizeTarget(target string) (*url.URL, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	if parsed.Scheme == "" {
		return url.Parse("https://" + target)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid target URL: %s", target)
	}

	return parsed, nil
}

func resolveURL(base *url.URL, location string) (*url.URL, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, err
	}

	return base.ResolveReference(parsed), nil
}

func isRedirect(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func FetchWithTLSConfig(target string, tlsConfig *tls.Config) (*FetchResult, error) {
	initialURL, err := normalizeTarget(target)
	if err != nil {
		return nil, err
	}

	resp, err := fetchOnce(initialURL.String(), false, tlsConfig)
	if err != nil {
		return nil, err
	}

	result := &FetchResult{
		InitialURL: initialURL,
		Response:   resp,
	}

	// For specific TLS config probes, we usually don't follow redirects
	// and are interested in the immediate connection state.
	// However, if a redirect occurs, we capture it.
	if isRedirect(resp.StatusCode) {
		location := resp.Header.Get("Location")
		if location == "" {
			resp.Body.Close()
			return nil, fmt.Errorf("redirect response missing Location header")
		}

		redirectURL, err := resolveURL(initialURL, location)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to resolve redirect URL: %w", err)
		}
		result.RedirectTarget = redirectURL
		result.Redirected = true
		// Don't follow redirect for this specific probe, just record it.
	}

	result.FinalURL = resp.Request.URL
	return result, nil
}
