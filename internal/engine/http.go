package engine

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewHTTPClient(allowRedirect bool, tlsConfig *tls.Config) *http.Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Timeout: 11 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	if !allowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}
