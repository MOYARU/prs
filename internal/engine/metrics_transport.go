package engine

import (
	"net/http"
	"sync/atomic"
	"time"
)

// MetricsTransport records request count and cumulative duration.
type MetricsTransport struct {
	Base      http.RoundTripper
	requests  int64
	durationN int64
}

func (t *MetricsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	atomic.AddInt64(&t.requests, 1)
	atomic.AddInt64(&t.durationN, time.Since(start).Nanoseconds())
	return resp, err
}

func (t *MetricsTransport) Snapshot() (int64, time.Duration) {
	return atomic.LoadInt64(&t.requests), time.Duration(atomic.LoadInt64(&t.durationN))
}
