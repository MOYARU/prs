package crawler

import (
	"bufio"
	"context"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MOYARU/prs/internal/app/ui"
	"github.com/MOYARU/prs/internal/engine"
	"golang.org/x/net/html"
)

var jsURLRegex = regexp.MustCompile(`(?:"|')(((?:https?://|/)[^"'\s<>]+))(?:"|')`)

const (
	maxCrawlTargets      = 1000
	maxResponseBodyBytes = 2 << 20 // 2 MiB
	maxLinksPerPage      = 500
)

var staticAssetExt = map[string]struct{}{
	".png":   {},
	".jpg":   {},
	".jpeg":  {},
	".gif":   {},
	".svg":   {},
	".webp":  {},
	".ico":   {},
	".pdf":   {},
	".zip":   {},
	".rar":   {},
	".7z":    {},
	".mp3":   {},
	".mp4":   {},
	".avi":   {},
	".mov":   {},
	".woff":  {},
	".woff2": {},
	".ttf":   {},
	".eot":   {},
}

type Crawler struct {
	BaseURL        *url.URL
	MaxDepth       int
	RespectRobots  bool
	Visited        map[string]bool
	Queued         map[string]bool
	VisitedSitemap map[string]bool
	Results        []string
	Client         *http.Client
	mu             sync.Mutex
	sem            chan struct{}
	wg             sync.WaitGroup
}

type Form struct {
	ActionURL string
	Method    string
	Inputs    []FormInput
}

type FormInput struct {
	Name  string
	Type  string
	Value string
}

func New(target string, depth int, delay time.Duration) (*Crawler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	client := engine.NewHTTPClient(true, nil)
	if delay > 0 {
		client.Transport = &engine.DelayedTransport{
			Transport: client.Transport,
			Delay:     delay,
		}
	}

	return &Crawler{
		BaseURL:        u,
		MaxDepth:       depth,
		RespectRobots:  false,
		Visited:        make(map[string]bool),
		Queued:         make(map[string]bool),
		VisitedSitemap: make(map[string]bool),
		Results:        []string{},
		Client:         client,
		sem:            make(chan struct{}, 10),
	}, nil
}

func (c *Crawler) SetRespectRobots(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RespectRobots = enabled
}

func (c *Crawler) Start(ctx context.Context) []string {
	ctx, cancel := ui.WaitForCancel(ctx)
	defer cancel()

	c.scheduleCrawl(ctx, c.BaseURL.String(), 0)

	c.wg.Add(1)
	go c.processRobotsAndSitemap(ctx)

	c.wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Strings(c.Results)
	return append([]string(nil), c.Results...)
}

func (c *Crawler) crawl(ctx context.Context, targetURL string, depth int) {
	defer c.wg.Done()

	select {
	case <-ctx.Done():
		return
	default:
	}

	if depth > c.MaxDepth {
		return
	}

	c.mu.Lock()
	c.Visited[targetURL] = true
	c.Results = append(c.Results, targetURL)
	c.mu.Unlock()

	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	if resp.Request != nil && resp.Request.URL != nil {
		u = resp.Request.URL
	}
	if finalURL, ok := c.normalizeURL(u.String()); ok && finalURL != targetURL {
		c.mu.Lock()
		if c.Visited[finalURL] {
			c.mu.Unlock()
			return
		}
		c.Visited[finalURL] = true
		c.Results = append(c.Results, finalURL)
		c.mu.Unlock()
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml")
	isJS := strings.Contains(contentType, "javascript") || strings.HasSuffix(strings.ToLower(u.Path), ".js")

	if !isHTML && !isJS {
		return
	}

	var links []string
	resolveBase := u

	if isHTML {
		doc, err := html.Parse(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if err != nil {
			return
		}

		var pageBase *url.URL
		links, pageBase = c.extractData(doc)

		if pageBase != nil {
			resolveBase = u.ResolveReference(pageBase)
		}
	} else {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if err != nil {
			return
		}
		links = c.extractLinksFromJS(string(bodyBytes))
	}

	links = dedupeAndLimitLinks(links, maxLinksPerPage)
	for _, link := range links {
		absoluteURL := c.resolveURL(resolveBase, link)
		c.scheduleCrawl(ctx, absoluteURL, depth+1)
	}
}

func (c *Crawler) scheduleCrawl(ctx context.Context, targetURL string, depth int) {
	if depth > c.MaxDepth {
		return
	}
	if targetURL == "" {
		return
	}

	normalized, ok := c.normalizeURL(targetURL)
	if !ok || !c.isSameDomain(normalized) || shouldSkipByExtension(normalized) {
		return
	}

	c.mu.Lock()
	if len(c.Queued) >= maxCrawlTargets || c.Queued[normalized] || c.Visited[normalized] {
		c.mu.Unlock()
		return
	}
	c.Queued[normalized] = true
	c.wg.Add(1)
	c.mu.Unlock()

	go c.crawl(ctx, normalized, depth)
}

func (c *Crawler) normalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}

	if u.Scheme == "" {
		u.Scheme = c.BaseURL.Scheme
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		u.Host = c.BaseURL.Host
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}

	port := u.Port()
	switch {
	case u.Scheme == "http" && port == "80":
		u.Host = host
	case u.Scheme == "https" && port == "443":
		u.Host = host
	case port != "":
		u.Host = net.JoinHostPort(host, port)
	default:
		u.Host = host
	}

	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	if u.Path != "/" && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	if u.RawQuery != "" {
		parsed, err := url.ParseQuery(u.RawQuery)
		if err == nil {
			u.RawQuery = parsed.Encode()
		}
	}
	return u.String(), true
}

func shouldSkipByExtension(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	ext := strings.ToLower(path.Ext(u.Path))
	_, skip := staticAssetExt[ext]
	return skip
}

func dedupeAndLimitLinks(links []string, limit int) []string {
	if len(links) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(links))
	out := make([]string, 0, len(links))
	for _, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		if _, exists := seen[link]; exists {
			continue
		}
		seen[link] = struct{}{}
		out = append(out, link)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (c *Crawler) extractData(n *html.Node) ([]string, *url.URL) {
	var links []string
	var base *url.URL

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "base":
				if base == nil {
					for _, a := range n.Attr {
						if a.Key == "href" {
							if parsedBase, err := url.Parse(a.Val); err == nil {
								base = parsedBase
							}
						}
					}
				}
			case "a", "area", "link":
				for _, a := range n.Attr {
					if a.Key == "href" {
						links = append(links, a.Val)
					}
				}
			case "script", "iframe", "frame", "img", "embed", "source", "track":
				for _, a := range n.Attr {
					if a.Key == "src" {
						links = append(links, a.Val)
					}
				}
			case "object":
				for _, a := range n.Attr {
					if a.Key == "data" {
						links = append(links, a.Val)
					}
				}
			case "form":
				for _, a := range n.Attr {
					if a.Key == "action" {
						links = append(links, a.Val)
					}
				}
			case "meta":
				var httpEquiv, content string
				for _, a := range n.Attr {
					k := strings.ToLower(a.Key)
					if k == "http-equiv" {
						httpEquiv = strings.ToLower(a.Val)
					} else if k == "content" {
						content = a.Val
					}
				}
				if httpEquiv == "refresh" {
					if idx := strings.Index(strings.ToLower(content), "url="); idx != -1 {
						urlPart := content[idx+4:]
						urlPart = strings.Trim(urlPart, "'\" ")
						links = append(links, urlPart)
					}
				}
			case "button", "input":
				for _, a := range n.Attr {
					if a.Key == "formaction" {
						links = append(links, a.Val)
					}
				}
			}

			for _, a := range n.Attr {
				k := strings.ToLower(a.Key)
				if k == "onclick" || k == "onmousedown" || k == "onmouseup" {
					val := a.Val
					if strings.Contains(val, "location") || strings.Contains(val, "open") || strings.Contains(val, "window") {
						for _, quote := range []string{"'", "\""} {
							parts := strings.Split(val, quote)
							for i := 1; i < len(parts); i += 2 {
								candidate := strings.TrimSpace(parts[i])
								if candidate != "" {
									links = append(links, candidate)
								}
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return links, base
}

func (c *Crawler) extractLinksFromJS(content string) []string {
	var links []string
	matches := jsURLRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}
	return links
}

func ExtractForms(n *html.Node) []Form {
	var forms []Form
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := Form{Method: "GET"}
			for _, a := range n.Attr {
				if a.Key == "action" {
					form.ActionURL = a.Val
				}
				if a.Key == "method" {
					form.Method = strings.ToUpper(a.Val)
				}
			}
			form.Inputs = ExtractInputs(n)
			forms = append(forms, form)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return forms
}

func ExtractInputs(n *html.Node) []FormInput {
	var inputs []FormInput
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.Data == "input" {
				input := FormInput{Type: "text"}
				for _, a := range n.Attr {
					if a.Key == "name" {
						input.Name = a.Val
					}
					if a.Key == "type" {
						input.Type = a.Val
					}
					if a.Key == "value" {
						input.Value = a.Val
					}
				}
				if input.Name != "" {
					inputs = append(inputs, input)
				}
			} else if n.Data == "textarea" {
				for _, a := range n.Attr {
					if a.Key == "name" {
						inputs = append(inputs, FormInput{Name: a.Val, Type: "textarea"})
					}
				}
			} else if n.Data == "select" {
				name := ""
				for _, a := range n.Attr {
					if a.Key == "name" {
						name = a.Val
						break
					}
				}
				if name != "" {
					inputs = append(inputs, FormInput{Name: name, Type: "select"})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return inputs
}

func (c *Crawler) resolveURL(baseURL *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	refLower := strings.ToLower(ref)
	if strings.HasPrefix(refLower, "#") ||
		strings.HasPrefix(refLower, "javascript:") ||
		strings.HasPrefix(refLower, "mailto:") ||
		strings.HasPrefix(refLower, "tel:") ||
		strings.HasPrefix(refLower, "data:") {
		return ""
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	normalized, ok := c.normalizeURL(baseURL.ResolveReference(refURL).String())
	if !ok {
		return ""
	}
	return normalized
}

func (c *Crawler) isSameDomain(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}

	linkHost := strings.ToLower(u.Hostname())
	baseHost := strings.ToLower(c.BaseURL.Hostname())
	return linkHost == baseHost || strings.HasSuffix(linkHost, "."+baseHost)
}

func (c *Crawler) processRobotsAndSitemap(ctx context.Context) {
	defer c.wg.Done()

	robotsURL := c.BaseURL.ResolveReference(&url.URL{Path: "/robots.txt"})
	c.parseRobotsTXT(ctx, robotsURL.String())

	sitemapURL := c.BaseURL.ResolveReference(&url.URL{Path: "/sitemap.xml"})
	c.parseSitemapXML(ctx, sitemapURL.String())
}

func (c *Crawler) parseRobotsTXT(ctx context.Context, targetURL string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.SplitN(line, "#", 2)[0]
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "disallow:") || strings.HasPrefix(lower, "allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				pathValue := strings.TrimSpace(parts[1])
				if pathValue != "" && strings.HasPrefix(pathValue, "/") {
					if c.RespectRobots && strings.HasPrefix(lower, "disallow:") {
						continue
					}
					absoluteURL := c.BaseURL.ResolveReference(&url.URL{Path: pathValue}).String()
					c.scheduleCrawl(ctx, absoluteURL, c.estimateDepthFromBase(absoluteURL))
				}
			}
		}

		if strings.HasPrefix(lower, "sitemap:") {
			sitemapLoc := strings.TrimSpace(line[len("sitemap:"):])
			if sitemapLoc != "" {
				c.parseSitemapXML(ctx, sitemapLoc)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return
	}
}

func (c *Crawler) parseSitemapXML(ctx context.Context, targetURL string) {
	normalizedSitemapURL, ok := c.normalizeURL(targetURL)
	if !ok {
		return
	}

	c.mu.Lock()
	if c.VisitedSitemap[normalizedSitemapURL] {
		c.mu.Unlock()
		return
	}
	c.VisitedSitemap[normalizedSitemapURL] = true
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedSitemapURL, nil)
	if err != nil {
		return
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	decoder := xml.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes))
	for {
		t, _ := decoder.Token()
		if t == nil {
			break
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		switch se := t.(type) {
		case xml.StartElement:
			if !strings.EqualFold(se.Name.Local, "loc") {
				continue
			}
			var loc string
			if err := decoder.DecodeElement(&loc, &se); err != nil {
				continue
			}
			loc = strings.TrimSpace(loc)
			if loc == "" || !c.isSameDomain(loc) {
				continue
			}
			if strings.HasSuffix(strings.ToLower(loc), ".xml") {
				c.parseSitemapXML(ctx, loc)
				continue
			}
			c.scheduleCrawl(ctx, loc, c.estimateDepthFromBase(loc))
		}
	}
}

func (c *Crawler) estimateDepthFromBase(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return c.MaxDepth + 1
	}

	basePathDepth := pathDepth(c.BaseURL.Path)
	targetPathDepth := pathDepth(u.Path)
	if targetPathDepth <= basePathDepth {
		return 0
	}
	return targetPathDepth - basePathDepth
}

func pathDepth(p string) int {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return 0
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return 0
	}
	return len(strings.Split(p, "/"))
}
