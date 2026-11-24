package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Result struct {
	URL              string
	Hostname         string
	Status           int
	StatusClass      string
	Classification   string
	Reason           string
	MatchedRule      string
	RedirectLocation string
}
type captures struct{ responses, baselines map[string]fingerprint }

func baselineKey(e Endpoint) string { return e.Origin + " " + parentDir(e.Path) }

func readCaptures(name string, scope Scope, targets []Endpoint) (captures, error) {
	data := captures{map[string]fingerprint{}, map[string]fingerprint{}}
	urls, dirs := map[string]bool{}, map[string]bool{}
	for _, e := range targets {
		urls[e.URL] = true
		dirs[baselineKey(e)] = true
	}
	if name == "" {
		return data, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return data, err
	}
	defer f.Close()
	err = readLines(f, func(_ int, line string) error {
		var c Capture
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return err
		}
		e, err := normalize(c.URL)
		if err != nil {
			return err
		}
		if _, ok := scope.match(e); !ok {
			return nil
		}
		if c.Status < 100 || c.Status > 599 {
			return fmt.Errorf("invalid HTTP status")
		}
		dst, key := data.responses, e.URL
		switch c.Kind {
		case "baseline":
			dst, key = data.baselines, baselineKey(e)
			if !dirs[key] {
				return nil
			}
			if urls[e.URL] {
				return fmt.Errorf("baseline URL is also a review target")
			}
		case "response":
			if !urls[key] {
				return nil
			}
		default:
			return fmt.Errorf("expected kind baseline or response")
		}
		if _, ok := dst[key]; ok {
			return fmt.Errorf("duplicate %s capture for %s", c.Kind, key)
		}
		dst[key] = makeFingerprint(c, e)
		return nil
	})
	return data, err
}

func review(targets []Endpoint, s Scope, c captures) []Result {
	out := make([]Result, 0, len(targets))
	for _, e := range targets {
		rule, ok := s.match(e)
		if !ok {
			continue
		}
		r := Result{URL: e.URL, Hostname: e.Hostname, StatusClass: "NO_CAPTURE", Classification: "UNCONFIRMED", Reason: "no saved response", MatchedRule: rule}
		if f, ok := c.responses[e.URL]; ok {
			r.Status = f.status
			r.StatusClass = statusClass(f.status)
			if f.status >= 300 && f.status < 400 {
				r.RedirectLocation = f.redirect
			}
			var b *fingerprint
			if baseline, ok := c.baselines[baselineKey(e)]; ok {
				b = &baseline
			}
			r.Classification, r.Reason = classify(f, b)
		}
		out = append(out, r)
	}
	return out
}
