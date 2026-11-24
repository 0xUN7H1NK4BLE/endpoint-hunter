package main

import (
	"crypto/sha256"
	"hash/fnv"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

type Capture struct {
	Kind      string      `json:"kind"`
	URL       string      `json:"url"`
	Status    int         `json:"status"`
	Headers   http.Header `json:"headers"`
	Body      *string     `json:"body"`
	Truncated bool        `json:"truncated"`
}
type fingerprint struct {
	status                            int
	media, location, challenge, allow string
	redirect                          string
	digest                            [32]byte
	length                            int
	sketch                            []uint64
	complete                          bool
}

func maskRequest(s string, e Endpoint) string {
	// Treat echoed paths as incidental only when the path is specific.
	if len(e.Path) > 1 {
		s = strings.ReplaceAll(s, e.URL, "{request}")
		s = strings.ReplaceAll(s, url.QueryEscape(e.Path), "{path}")
		s = strings.ReplaceAll(s, e.Path, "{path}")
	}
	return s
}

// The lowest 64 unique word-bigram hashes form a bounded similarity sketch.
func bodySketch(words []string) []uint64 {
	if len(words) < 5 {
		return nil
	}
	hashes := make([]uint64, 0, len(words)-1)
	for i := 1; i < len(words); i++ {
		h := fnv.New64a()
		h.Write([]byte(words[i-1]))
		h.Write([]byte{0})
		h.Write([]byte(words[i]))
		hashes = append(hashes, h.Sum64())
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })
	sketch := make([]uint64, 0, 64)
	for _, v := range hashes {
		if len(sketch) == 0 || sketch[len(sketch)-1] != v {
			sketch = append(sketch, v)
			if len(sketch) == 64 {
				break
			}
		}
	}
	return sketch
}

func makeFingerprint(c Capture, e Endpoint) fingerprint {
	h := make(http.Header)
	for k, values := range c.Headers {
		for _, v := range values {
			h.Add(k, v)
		}
	}
	media, _, _ := strings.Cut(h.Get("Content-Type"), ";")
	location := h.Get("Location")
	if location != "" {
		base, _ := url.Parse(e.URL)
		if dest, err := base.Parse(location); err == nil {
			location = dest.String()
		}
	}
	location = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, location))
	f := fingerprint{status: c.Status, media: strings.ToLower(strings.TrimSpace(media)), location: maskRequest(location, e), redirect: location, challenge: h.Get("WWW-Authenticate"), allow: h.Get("Allow"), complete: c.Body != nil && !c.Truncated}
	if f.complete {
		words := strings.Fields(maskRequest(*c.Body, e))
		body := strings.Join(words, " ")
		f.length = len(body)
		f.digest = sha256.Sum256([]byte(body))
		f.sketch = bodySketch(words)
	}
	return f
}

func similarity(a, b []uint64) float64 {
	i, j, common, total := 0, 0, 0, 0
	for total < 64 && (i < len(a) || j < len(b)) {
		switch {
		case j == len(b) || i < len(a) && a[i] < b[j]:
			i++
		case i == len(a) || b[j] < a[i]:
			j++
		default:
			i++
			j++
			common++
		}
		total++
	}
	if total == 0 {
		return 0
	}
	return float64(common) / float64(total)
}

func statusClass(s int) string {
	switch {
	case s == 0:
		return "NO_CAPTURE"
	case s >= 200 && s <= 299:
		return "SUCCESS"
	case s >= 301 && s <= 308:
		return "REDIRECT"
	case s == 400 || s == 409 || s == 422:
		return "POTENTIAL"
	case s == 401:
		return "AUTH_REQUIRED"
	case s == 403:
		return "FORBIDDEN"
	case s == 404:
		return "NOT_FOUND"
	case s == 405:
		return "METHOD_NOT_ALLOWED"
	case s == 429:
		return "RATE_LIMITED"
	case s >= 500 && s <= 599:
		return "SERVER_ERROR"
	default:
		return "OTHER"
	}
}

func classify(f fingerprint, b *fingerprint) (string, string) {
	if f.status == 404 || f.status == 410 {
		return "NOT_FOUND", "captured explicit missing-resource response"
	}
	if b == nil {
		return "UNCONFIRMED", "no baseline captured for this origin and directory"
	}
	if !usableBaseline(b.status) {
		return "UNCONFIRMED", "baseline status unsuitable for comparison"
	}
	if !f.complete || !b.complete {
		return "UNCONFIRMED", "comparison requires two complete captured bodies"
	}
	sameMeta := f.status == b.status && f.media == b.media && f.location == b.location && f.challenge == b.challenge && f.allow == b.allow
	closeLength := math.Abs(float64(f.length-b.length)) <= 0.1*float64(max(f.length, b.length))
	similar := len(f.sketch) >= 8 && len(b.sketch) >= 8 && similarity(f.sketch, b.sketch) >= 0.85
	matches := sameMeta && (f.digest == b.digest || closeLength && similar)
	group := statusClass(f.status)
	if matches {
		if group == "REDIRECT" || f.status == 401 || f.status == 403 || f.length == 0 {
			return "UNCONFIRMED", "baseline has the same redirect, access gate, or empty response"
		}
		return "NOT_FOUND", "response matches the supplied missing-route baseline"
	}
	switch group {
	case "REDIRECT":
		if f.location != "" && f.location != b.location {
			return "REDIRECT", "captured redirect destination differs from baseline"
		}
	case "FORBIDDEN", "AUTH_REQUIRED":
		if f.status != b.status || f.challenge != b.challenge {
			return "RESTRICTED", "access response differs from baseline status or challenge"
		}
	case "SUCCESS", "POTENTIAL", "METHOD_NOT_ALLOWED":
		if f.status != b.status || f.media != b.media || f.allow != b.allow || (!closeLength && !similar && f.length > 0 && b.length > 0) {
			return "POTENTIAL", "status, representation, or allowed methods differ from baseline"
		}
	}
	return "UNCONFIRMED", "insufficient distinguishing evidence"
}
func usableBaseline(s int) bool {
	return (s >= 200 && s <= 299) || (s >= 301 && s <= 308) || s == 401 || s == 403 || s == 404 || s == 410
}
