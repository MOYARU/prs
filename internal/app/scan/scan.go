package scan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MOYARU/prs/internal/app/output"
	"github.com/MOYARU/prs/internal/app/ui"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	"github.com/MOYARU/prs/internal/checks/scanner"
	"github.com/MOYARU/prs/internal/config"
	"github.com/MOYARU/prs/internal/crawler"
	"github.com/MOYARU/prs/internal/engine"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
	"golang.org/x/net/publicsuffix"
)

func RunScan(target string, activeScan bool, crawl bool, respectRobots bool, depth int, jsonOutput bool, htmlOutput bool, delay int, allowPrompts bool) error {
	normalizedTarget, err := normalizeTarget(target)
	if err != nil {
		return err
	}
	target = normalizedTarget

	// Fast-fail for invalid/non-existent hosts to improve user feedback.
	if err := validateTargetHost(target); err != nil {
		return fmt.Errorf("target is not reachable: %w", err)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer signal.Stop(c)
	go func() {
		select {
		case <-c:
			fmt.Println(ui.ColorYellow + msges.GetUIMessage("ScanCancelled") + ui.ColorReset)
			cancel()
		case <-ctx.Done():
		}
	}()

	// Active scan safety check
	if activeScan && allowPrompts {
		fmt.Printf("\n%s%s%s\n", ui.ColorRed, msges.GetUIMessage("ActiveScanWarning"), ui.ColorReset)
		fmt.Printf("%s%s%s\n", ui.ColorYellow, msges.GetUIMessage("ActiveScanPermission"), ui.ColorReset)

		prompt := fmt.Sprintf("%s%s%s", ui.ColorYellow, msges.GetUIMessage("ActiveScanPrompt"), ui.ColorReset)
		confirmed, err := ui.Confirm(prompt)
		if err != nil || !confirmed {
			fmt.Printf("\n%s%s%s\n", ui.ColorYellow, msges.GetUIMessage("ActiveScanAborted"), ui.ColorReset)
			return fmt.Errorf("active scan aborted by user")
		}
	}

	fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("Target", target), ui.ColorReset)

	if activeScan {
		fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ModeActive"), ui.ColorReset)
	} else {
		fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ModePassive"), ui.ColorReset)
	}

	fmt.Printf("%s%s%s\n", ui.ColorGray, msges.GetUIMessage("StatusReady"), ui.ColorReset)

	mode := ctxpkg.Passive
	if activeScan {
		mode = ctxpkg.Active
	}

	delayDuration := time.Duration(delay) * time.Millisecond
	policy := config.LoadScanPolicyFromPRS()

	var targets []string
	if crawl {
		c, err := crawler.New(target, depth, delayDuration)
		if err != nil {
			return fmt.Errorf("failed to initialize crawler: %w", err)
		}
		c.SetRespectRobots(respectRobots)
		stopReadyDots := startStatusDots(ctx, msges.GetUIMessage("StatusReady"))
		targets = c.Start(ctx) // Pass context
		stopReadyDots()
		fmt.Printf("%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("CrawlingComplete", len(targets)), ui.ColorReset)
	} else {
		targets = []string{target}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no reachable targets discovered from %s", target)
	}
	if activeScan && len(targets) > 1 {
		targets = prioritizeTargets(targets)
	}

	// Check if cancelled during crawl
	if ctx.Err() != nil {
		return nil
	}

	// Display Crawled Scope
	if len(targets) > 1 {
		fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("CrawledScope"), ui.ColorReset)
		for _, t := range targets {
			fmt.Printf(" - %s\n", t)
		}
		fmt.Println()
	}

	var allFindings []report.Finding
	// Track unique findings per check to calculate counts correctly
	checkUniqueFindings := make(map[string]map[string]bool) // CheckID -> Set of (ID|Message)
	checksRan := make(map[string]bool)
	checkPerf := make(map[string]scanner.CheckStat)

	startTime := time.Now()

	type findingKey struct {
		ID      string
		Message string
	}
	type findingInfo struct {
		Finding report.Finding
		URLs    map[string]bool
		CheckID string
	}
	aggregatedFindings := make(map[findingKey]*findingInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	var scanErrors []string
	var completedCount int32
	output.PrintScanProgress(0, len(targets), "Ready", "")

	// Create a shared client for connection pooling
	sharedClient := engine.NewHTTPClient(false, nil)
	rootDomain := rootDomainFromURL(target)
	if delay > 0 {
		sharedClient.Transport = &engine.DelayedTransport{
			Transport: sharedClient.Transport,
			Delay:     delayDuration,
		}
	}
	if activeScan && !policy.ActiveCrossDomain {
		sharedClient.Transport = &engine.DomainBoundaryTransport{
			Base:              sharedClient.Transport,
			AllowedRootDomain: rootDomain,
		}
	}
	// Safety policy: prevent runaway request explosions in active scans.
	requestBudget := policy.RequestBudget
	if requestBudget == 0 {
		requestBudget = int64(300 + len(targets)*40)
	}
	sharedClient.Transport = &engine.RequestBudgetTransport{
		Base: sharedClient.Transport,
		Max:  requestBudget,
	}

	workerCount := policy.MaxConcurrency
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	targetQueue := make(chan string)
	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case urlStr, ok := <-targetQueue:
				if !ok {
					return
				}

				// Update progress bar on completion (defer to ensure it runs even on error)
				func() {
					defer func() {
						newCount := atomic.AddInt32(&completedCount, 1)
						output.PrintScanProgress(int(newCount), len(targets), "Scanning", urlStr)
					}()

					if ctx.Err() != nil {
						return
					}

					scn, err := scanner.New(urlStr, mode, delayDuration, sharedClient, policy.PassiveProfile)
					if err != nil {
						mu.Lock()
						scanErrors = append(scanErrors, msges.GetUIMessage("ScannerInitFailed", urlStr, err))
						mu.Unlock()
						return
					}

					resultsByCheck, checkErrors, statsByCheck, err := scn.Run(ctx)
					if err != nil {
						mu.Lock()
						scanErrors = append(scanErrors, msges.GetUIMessage("ScanFailed", urlStr, err))
						mu.Unlock()
						return
					}

					mu.Lock()
					defer mu.Unlock()

					for checkID, findings := range resultsByCheck {
						checksRan[checkID] = true
						if checkUniqueFindings[checkID] == nil {
							checkUniqueFindings[checkID] = make(map[string]bool)
						}

						for _, f := range findings {
							f = report.ApplySeverityOverride(f)
							f.EvidenceQuality = report.ScoreEvidenceQuality(f)
							f = report.SanitizeFinding(f)

							// Global aggregation
							keyMessage := f.Message
							if f.ID == "MISSING_SECURITY_HEADERS" {
								if domain := rootDomainFromURL(urlStr); domain != "" {
									keyMessage = "root-domain:" + domain
								}
							}
							k := findingKey{ID: f.ID, Message: keyMessage}
							if _, exists := aggregatedFindings[k]; !exists {
								aggregatedFindings[k] = &findingInfo{
									Finding: f,
									URLs:    make(map[string]bool),
									CheckID: checkID,
								}
							}
							aggregatedFindings[k].URLs[urlStr] = true

							// Per-check unique counting
							uniqueKey := f.ID + "|" + f.Message
							checkUniqueFindings[checkID][uniqueKey] = true
						}
					}
					for checkID, st := range statsByCheck {
						prev := checkPerf[checkID]
						checkPerf[checkID] = scanner.CheckStat{
							Requests: prev.Requests + st.Requests,
							Duration: prev.Duration + st.Duration,
						}
					}

					for checkID, checkErr := range checkErrors {
						checksRan[checkID] = true
						scanErrors = append(scanErrors, fmt.Sprintf("check '%s' failed on %s: %v", checkID, urlStr, checkErr))
					}
				}()
			}
		}
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			close(targetQueue)
			wg.Wait()
			return nil
		case targetQueue <- t:
		}
	}
	close(targetQueue)
	wg.Wait()

	findingsByCheck := make(map[string][]report.Finding)

	// Convert aggregated map to slice
	for _, info := range aggregatedFindings {
		f := info.Finding

		for u := range info.URLs {
			f.AffectedURLs = append(f.AffectedURLs, report.SanitizeURL(u))
		}

		allFindings = append(allFindings, f)
		if info.CheckID != "" {
			findingsByCheck[info.CheckID] = append(findingsByCheck[info.CheckID], f)
		}
	}

	// Derive chained attack-path findings from combined evidence.
	chainedFindings := buildChainedFindings(allFindings)
	for _, f := range chainedFindings {
		f = report.ApplySeverityOverride(f)
		f.EvidenceQuality = report.ScoreEvidenceQuality(f)
		f = report.SanitizeFinding(f)
		allFindings = append(allFindings, f)
	}

	endTime := time.Now()
	elapsed := endTime.Sub(startTime).Seconds()
	fmt.Printf("\n%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("AllScansCompleted"), ui.ColorReset)
	fmt.Printf("%sScan completed in %.2fs%s\n", ui.ColorGray, elapsed, ui.ColorReset)

	// Print any scan errors that occurred
	if len(scanErrors) > 0 {
		fmt.Printf("\n%sErrors encountered during scan:%s\n", ui.ColorRed, ui.ColorReset)
		for _, errMsg := range scanErrors {
			fmt.Printf(" - %s\n", errMsg)
		}
	}

	// Calculate final counts per check
	checkCounts := make(map[string]int)
	for id, uniqueSet := range checkUniqueFindings {
		checkCounts[id] = len(uniqueSet)
	}

	output.PrintFindings(allFindings)
	output.PrintScanSummary(checkCounts, checksRan, findingsByCheck)

	if jsonOutput {
		sanitizedTargets := make([]string, 0, len(targets))
		for _, t := range targets {
			sanitizedTargets = append(sanitizedTargets, report.SanitizeURL(t))
		}
		if err := output.SaveJSONReport(report.SanitizeURL(target), sanitizedTargets, allFindings, checkPerf, startTime, endTime); err != nil {
			fmt.Printf("[Error] %s\n", msges.GetUIMessage("JSONReportFailed", err))
		}
	}

	if htmlOutput {
		sanitizedTargets := make([]string, 0, len(targets))
		for _, t := range targets {
			sanitizedTargets = append(sanitizedTargets, report.SanitizeURL(t))
		}
		if err := output.SaveHTMLReport(report.SanitizeURL(target), sanitizedTargets, allFindings, checkPerf, startTime, endTime); err != nil {
			fmt.Printf("%s\n", msges.GetUIMessage("HTMLReportFailed", err))
		}
	}
	return nil
}

func isHTTPSReachable(target string) bool {
	probe := target
	if !strings.HasPrefix(probe, "http://") && !strings.HasPrefix(probe, "https://") {
		probe = "https://" + probe
	}
	parsed, err := url.Parse(probe)
	if err != nil || parsed.Host == "" {
		return false
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	httpsURL := &url.URL{
		Scheme: "https",
		Host:   parsed.Host,
		Path:   "/",
	}
	req, err := http.NewRequest(http.MethodHead, httpsURL.String(), nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return true
	}
	return false
}

func normalizeTarget(rawTarget string) (string, error) {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return "", fmt.Errorf("target is empty")
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		if isHTTPSReachable(target) {
			target = "https://" + target
		} else {
			target = "http://" + target
		}
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme: %s (only http/https allowed)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid target URL: missing host")
	}
	return parsed.String(), nil
}

func validateTargetHost(target string) error {
	parsed, err := url.Parse(target)
	if err != nil {
		return err
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IP address found for %s", host)
	}

	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("connection to %s failed: %w", net.JoinHostPort(host, port), err)
	}
	_ = conn.Close()
	return nil
}

func rootDomainFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return ""
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return root
}

func prioritizeTargets(targets []string) []string {
	scored := make([]string, len(targets))
	copy(scored, targets)
	sort.SliceStable(scored, func(i, j int) bool {
		si := targetRiskScore(scored[i])
		sj := targetRiskScore(scored[j])
		if si == sj {
			return scored[i] < scored[j]
		}
		return si > sj
	})
	return scored
}

func targetRiskScore(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}

	path := strings.ToLower(u.Path)
	score := 0
	if strings.Contains(path, "admin") || strings.Contains(path, "api") || strings.Contains(path, "account") || strings.Contains(path, "profile") || strings.Contains(path, "auth") {
		score += 5
	}
	if strings.Contains(path, "search") || strings.Contains(path, "query") || strings.Contains(path, "redirect") || strings.Contains(path, "callback") {
		score += 4
	}

	q := u.Query()
	for name := range q {
		n := strings.ToLower(name)
		switch {
		case strings.Contains(n, "id"), strings.Contains(n, "user"), strings.Contains(n, "account"), strings.Contains(n, "uid"):
			score += 4
		case strings.Contains(n, "url"), strings.Contains(n, "redirect"), strings.Contains(n, "next"), strings.Contains(n, "return"):
			score += 4
		case strings.Contains(n, "q"), strings.Contains(n, "search"), strings.Contains(n, "query"), strings.Contains(n, "keyword"):
			score += 3
		case strings.Contains(n, "file"), strings.Contains(n, "path"), strings.Contains(n, "doc"):
			score += 3
		case strings.Contains(n, "token"), strings.Contains(n, "auth"), strings.Contains(n, "key"), strings.Contains(n, "session"):
			score += 2
		default:
			score++
		}
	}
	return score
}

func startStatusDots(ctx context.Context, base string) func() {
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		dots := 0
		for {
			select {
			case <-ctx.Done():
				fmt.Printf("\r%s%s%s\033[K\n", ui.ColorGray, base, ui.ColorReset)
				return
			case <-stopCh:
				fmt.Printf("\r%s%s%s\033[K\n", ui.ColorGray, base, ui.ColorReset)
				return
			case <-ticker.C:
				dots = (dots + 1) % 4
				fmt.Printf("\r%s%s%s%s\033[K", ui.ColorGray, base, strings.Repeat(".", dots), ui.ColorReset)
			}
		}
	}()

	return func() {
		close(stopCh)
		<-doneCh
	}
}
