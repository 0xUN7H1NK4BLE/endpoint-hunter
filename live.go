package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 256 << 10

type liveOptions struct {
	Concurrency int
	Timeout     time.Duration
	Rate        float64
	UserAgent   string
	Headers     http.Header
}

// headerFlags implements repeatable -H options. Parsing is deferred until
// after flag.Parse so flag errors never echo a secret header value.
type headerFlags struct{ lines []string }

func (h *headerFlags) String() string {
	if len(h.lines) == 0 {
		return ""
	}
	return "<set>"
}

func (h *headerFlags) Set(line string) error {
	h.lines = append(h.lines, line)
	return nil
}

func (h *headerFlags) headers() (http.Header, error) {
	values := make(http.Header)
	for _, line := range h.lines {
		key, value, err := parseHeaderLine(line)
		if err != nil {
			return nil, fmt.Errorf("-H: %w", err)
		}
		values.Set(key, value)
	}
	return values, nil
}

type requestPacer struct {
	mu    sync.Mutex
	next  time.Time
	pause time.Time
	step  time.Duration
}

func newRequestPacer(rate float64) *requestPacer {
	p := &requestPacer{}
	if rate > 0 {
		p.step = time.Duration(float64(time.Second) / rate)
	}
	return p
}

func (p *requestPacer) wait(ctx context.Context) error {
	for {
		p.mu.Lock()
		now := time.Now()
		at := now
		if p.next.After(at) {
			at = p.next
		}
		if p.pause.After(at) {
			at = p.pause
		}
		if at.After(now) {
			p.mu.Unlock()
			timer := time.NewTimer(time.Until(at))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		p.next = now.Add(p.step)
		p.mu.Unlock()
		return nil
	}
}

func (p *requestPacer) retryAfter(value string) {
	if value == "" {
		return
	}
	var until time.Time
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		until = time.Now().Add(time.Duration(seconds) * time.Second)
	} else if date, err := http.ParseTime(value); err == nil {
		until = date
	}
	p.mu.Lock()
	if until.After(p.pause) {
		p.pause = until
	}
	p.mu.Unlock()
}

type liveScanner struct {
	scope  Scope
	client *http.Client
	pacer  *requestPacer
	opts   liveOptions
}

func newLiveScanner(scope Scope, opts liveOptions) (*liveScanner, error) {
	if opts.Concurrency < 1 || opts.Concurrency > 100 {
		return nil, fmt.Errorf("concurrency must be between 1 and 100")
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}
	if math.IsNaN(opts.Rate) || math.IsInf(opts.Rate, 0) || opts.Rate < 0 || opts.Rate > 1000 {
		return nil, fmt.Errorf("rate-limit must be between 0 and 1000 requests per second")
	}
	client := &http.Client{Timeout: opts.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &liveScanner{scope: scope, client: client, pacer: newRequestPacer(opts.Rate), opts: opts}, nil
}

func (s *liveScanner) fetch(ctx context.Context, e Endpoint) (fingerprint, int, error) {
	if _, ok := s.scope.match(e); !ok {
		return fingerprint{}, 0, fmt.Errorf("out of scope: %s", e.URL)
	}
	if err := s.pacer.wait(ctx); err != nil {
		return fingerprint{}, 0, err
	}
	// Scope is checked at the last point before any outbound request.
	if _, ok := s.scope.match(e); !ok {
		return fingerprint{}, 0, fmt.Errorf("out of scope: %s", e.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return fingerprint{}, 0, err
	}
	if _, supplied := s.opts.Headers["User-Agent"]; !supplied && s.opts.UserAgent != "" {
		req.Header.Set("User-Agent", s.opts.UserAgent)
	}
	for key, values := range s.opts.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fingerprint{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		s.pacer.retryAfter(resp.Header.Get("Retry-After"))
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if readErr != nil {
		f := makeFingerprint(Capture{URL: e.URL, Status: resp.StatusCode, Headers: resp.Header, Truncated: true}, e)
		return f, resp.StatusCode, readErr
	}
	truncated := len(body) > maxResponseBytes
	if truncated {
		body = body[:maxResponseBytes]
	}
	content := string(body)
	f := makeFingerprint(Capture{URL: e.URL, Status: resp.StatusCode, Headers: resp.Header, Body: &content, Truncated: truncated}, e)
	return f, resp.StatusCode, nil
}

func (s *liveScanner) baseline(ctx context.Context, targets []Endpoint) map[string]fingerprint {
	baseline := map[string]fingerprint{}
	visited := map[string]bool{}
	for _, e := range targets {
		if visited[e.Origin] {
			continue
		}
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			continue
		}
		base, err := normalize(e.Origin + strings.TrimSuffix(parentDir(e.Path), "/") + "/.endpoint-hunter-" + hex.EncodeToString(random[:]))
		if err != nil {
			continue
		}
		if _, ok := s.scope.match(base); !ok {
			continue
		}
		visited[e.Origin] = true
		f, _, err := s.fetch(ctx, base)
		if err == nil {
			baseline[e.Origin] = f
		}
	}
	return baseline
}

func (s *liveScanner) scan(ctx context.Context, targets []Endpoint, onResult func(Result) error) ([]Result, error) {
	baselines := s.baseline(ctx, targets)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan Endpoint)
	results := make(chan Result)
	var wg sync.WaitGroup
	for i := 0; i < s.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				rule, ok := s.scope.match(e)
				if !ok {
					continue
				}
				r := Result{URL: e.URL, Hostname: e.Hostname, MatchedRule: rule, StatusClass: "NO_RESPONSE", Classification: "UNCONFIRMED"}
				f, status, err := s.fetch(ctx, e)
				r.Status = status
				if status > 0 {
					r.StatusClass = statusClass(status)
					if status >= 300 && status < 400 {
						r.RedirectLocation = f.redirect
					}
				}
				if err != nil {
					r.Reason = err.Error()
				} else {
					if b, ok := baselines[e.Origin]; ok {
						r.Classification, r.Reason = classify(f, &b)
					} else {
						r.Classification, r.Reason = classify(f, nil)
					}
				}
				results <- r
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, e := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- e:
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	rows := make([]Result, 0, len(targets))
	var firstErr error
	for r := range results {
		rows = append(rows, r)
		if onResult != nil && firstErr == nil {
			firstErr = onResult(r)
			if firstErr != nil {
				cancel()
			}
		}
	}
	if firstErr != nil {
		return rows, firstErr
	}
	if err := ctx.Err(); err != nil {
		return rows, err
	}
	return rows, nil
}

func loadHeaders(name string) (http.Header, error) {
	h := make(http.Header)
	if name == "" {
		return h, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	err = readLines(f, func(_ int, line string) error {
		key, value, err := parseHeaderLine(line)
		if err != nil {
			return err
		}
		h.Add(key, value)
		return nil
	})
	return h, err
}

func parseHeaderLine(line string) (string, string, error) {
	key, value, ok := strings.Cut(line, ":")
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if !ok || key == "" || !validHeaderName(key) {
		return "", "", fmt.Errorf("expected Header-Name: value")
	}
	if strings.EqualFold(key, "Host") {
		return "", "", fmt.Errorf("Host header cannot be changed; use the target URL")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return "", "", fmt.Errorf("header value contains a control character")
		}
	}
	return key, value, nil
}

func validHeaderName(name string) bool {
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
