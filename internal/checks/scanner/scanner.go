package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/registry"
	"github.com/MOYARU/prs/internal/engine"
	"github.com/MOYARU/prs/internal/report"
)

type Scanner struct {
	Target         string
	Mode           ctxpkg.ScanMode
	Checks         []checks.Check
	client         *http.Client
	passiveProfile string
}

type CheckStat struct {
	Requests int64
	Duration time.Duration
}

func checkWorkerCount(totalChecks int, mode ctxpkg.ScanMode) int {
	if totalChecks <= 1 {
		return 1
	}

	// Keep per-target check fan-out bounded to avoid request bursts while still
	// using available CPU/network parallelism.
	limit := runtime.GOMAXPROCS(0) * 2
	if mode == ctxpkg.Active && limit > 8 {
		limit = 8
	}
	if mode == ctxpkg.Passive && limit > 12 {
		limit = 12
	}
	if limit < 4 {
		limit = 4
	}
	if totalChecks < limit {
		return totalChecks
	}
	return limit
}

func New(target string, mode ctxpkg.ScanMode, delay time.Duration, client *http.Client, passiveProfile string) (*Scanner, error) {
	if _, err := http.NewRequest("GET", target, nil); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if client == nil {
		client = engine.NewHTTPClient(false, nil)
	}

	profile := normalizePassiveProfile(passiveProfile)

	return &Scanner{
		Target:         target,
		Mode:           mode,
		Checks:         registry.DefaultChecks(),
		client:         client,
		passiveProfile: profile,
	}, nil
}

// Run executes all checks with context cancellation support.
// It returns findings by check ID, per-check execution errors, and per-check request stats.
func (s *Scanner) Run(ctx context.Context) (map[string][]report.Finding, map[string]error, map[string]CheckStat, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Target, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid target URL: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	bodyBytes, err := engine.DecodeResponseBody(resp)
	if err != nil {
		resp.Body.Close()
		return nil, nil, nil, fmt.Errorf("failed to decode response body: %w", err)
	}
	defer resp.Body.Close() // Close the original response body after reading

	initialURL := req.URL
	finalURL := resp.Request.URL
	redirected := initialURL.String() != finalURL.String()
	redirectedToHTTPS := initialURL.Scheme == "http" && finalURL.Scheme == "https"
	var redirectTarget *url.URL
	if redirected {
		redirectTarget = finalURL
	}

	scanCtx := &ctxpkg.Context{
		Target:            s.Target,
		RequestContext:    ctx,
		Mode:              s.Mode,
		InitialURL:        initialURL,
		FinalURL:          finalURL,
		Response:          resp,
		BodyBytes:         bodyBytes,
		RedirectTarget:    redirectTarget,
		Redirected:        redirected,
		RedirectedToHTTPS: redirectedToHTTPS,
		HTTPClient:        s.client,
	}

	resultsByCheck := make(map[string][]report.Finding)
	checkErrors := make(map[string]error)
	checkStats := make(map[string]CheckStat)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var checksToRun []checks.Check
	for _, check := range s.Checks {
		if s.Mode == ctxpkg.Passive && check.Mode == ctxpkg.Active {
			continue
		}
		if s.Mode == ctxpkg.Passive && !allowPassiveCheckByProfile(check.ID, s.passiveProfile) {
			continue
		}
		checksToRun = append(checksToRun, check)
	}
	sem := make(chan struct{}, checkWorkerCount(len(checksToRun), s.Mode))

	for _, check := range checksToRun {
		select {
		case <-ctx.Done():
			return resultsByCheck, checkErrors, checkStats, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			mt := &engine.MetricsTransport{Base: s.client.Transport}
			checkClient := *s.client
			checkClient.Transport = mt
			localCtx := *scanCtx
			localCtx.HTTPClient = &checkClient

			results, err := c.Run(&localCtx)
			reqCount, reqDuration := mt.Snapshot()

			mu.Lock()
			defer mu.Unlock()
			checkStats[c.ID] = CheckStat{
				Requests: reqCount,
				Duration: reqDuration,
			}

			if err != nil {
				if _, exists := checkErrors[c.ID]; !exists {
					checkErrors[c.ID] = err
				}
				return
			}

			resultsByCheck[c.ID] = results
		}(check)
	}
	wg.Wait()

	return resultsByCheck, checkErrors, checkStats, nil
}

func normalizePassiveProfile(v string) string {
	switch v {
	case "strict", "aggressive", "balanced":
		return v
	default:
		return "balanced"
	}
}

func allowPassiveCheckByProfile(checkID, profile string) bool {
	if profile == "aggressive" || profile == "balanced" {
		return true
	}
	// strict profile: prefer low-noise, concrete passive checks; skip weak heuristic indicators.
	switch checkID {
	case "PARAMETER_POLLUTION_PASSIVE",
		"METHOD_OVERRIDE_PASSIVE",
		"SSRF_PASSIVE",
		"SQL_INJECTION_PASSIVE",
		"REFLECTED_XSS_PASSIVE",
		"JSON_UNEXPECTED_FIELD_PASSIVE",
		"AUTH_SURFACE_PROFILE",
		"ATTACK_SURFACE_INTELLIGENCE",
		"CACHE_VARY_KEY_WEAK",
		"REQUEST_SMUGGLING_PASSIVE",
		"API_CONTRACT_DRIFT_PASSIVE":
		return false
	default:
		return true
	}
}
