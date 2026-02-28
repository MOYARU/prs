package context

import (
	"context"
	"net/http"
	"net/url"
)

type ScanMode string

const (
	Passive ScanMode = "passive"
	Active  ScanMode = "active"
)

type Context struct {
	Target            string
	RequestContext    context.Context
	Mode              ScanMode
	InitialURL        *url.URL
	FinalURL          *url.URL
	Response          *http.Response
	BodyBytes         []byte
	RedirectTarget    *url.URL
	Redirected        bool
	RedirectedToHTTPS bool
	HTTPClient        *http.Client
}
