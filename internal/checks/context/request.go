package context

import (
	"io"
	"net/http"
)

// NewRequest creates a request that inherits scan cancellation/timeout context when available.
func NewRequest(scanCtx *Context, method, target string, body io.Reader) (*http.Request, error) {
	if scanCtx != nil && scanCtx.RequestContext != nil {
		return http.NewRequestWithContext(scanCtx.RequestContext, method, target, body)
	}
	return http.NewRequest(method, target, body)
}
