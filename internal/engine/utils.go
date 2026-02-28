package engine

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
)

const maxDecodedBodyBytes = 4 << 20 // 4 MiB safety cap

// DecodeResponseBody attempts to decode a compressed HTTP response body.
func DecodeResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		r, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		reader = r
		defer reader.Close()
	default:
		reader = resp.Body
	}

	limited := io.LimitReader(reader, maxDecodedBodyBytes+1)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if len(bodyBytes) > maxDecodedBodyBytes {
		bodyBytes = bodyBytes[:maxDecodedBodyBytes]
	}
	return bodyBytes, nil
}
