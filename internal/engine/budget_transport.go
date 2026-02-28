package engine

import (
	"errors"
	"net/http"
	"sync/atomic"
)

var ErrRequestBudgetExceeded = errors.New("request budget exceeded")

// RequestBudgetTransport limits total outgoing requests for a scan run.
type RequestBudgetTransport struct {
	Base      http.RoundTripper
	Max       int64
	requested int64
}

func (t *RequestBudgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	next := atomic.AddInt64(&t.requested, 1)
	if t.Max > 0 && next > t.Max {
		return nil, ErrRequestBudgetExceeded
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
