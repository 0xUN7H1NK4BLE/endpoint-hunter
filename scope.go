package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type rule struct {
	raw      string
	hostOnly bool
	re       *regexp.Regexp
}
type Scope []rule

func readScope(r io.Reader) (Scope, error) {
	var rules Scope
	err := readLines(r, func(_ int, s string) error {
		original := s
		pattern, isRegex := strings.CutPrefix(s, "regex:")
		hostOnly := false
		if isRegex {
			if strings.TrimSpace(pattern) == "" {
				return fmt.Errorf("empty regex")
			}
		} else {
			hostOnly = !strings.Contains(s, "://")
			if hostOnly && strings.Contains(s, "/") {
				return fmt.Errorf("URL rules require a scheme")
			}
			if hostOnly {
				s = strings.ToLower(s)
			} else {
				// A scheme and authority without a route denotes the whole
				// origin. Keep path-specific rules exact unless they use wildcards.
				prefix, authority, _ := strings.Cut(s, "://")
				if authority != "" && (!strings.Contains(authority, "/") || strings.HasSuffix(authority, "/") && strings.Count(authority, "/") == 1) {
					if strings.ContainsAny(s, "*?") {
						s = strings.TrimSuffix(s, "/") + "/*"
					} else {
						e, err := normalize(prefix + "://" + authority)
						if err != nil {
							return fmt.Errorf("invalid origin scope rule: %w", err)
						}
						s = e.Origin + "/*"
					}
				}
			}
			var b strings.Builder
			b.WriteString("^")
			for _, c := range s {
				switch c {
				case '*':
					b.WriteString(".*")
				case '?':
					b.WriteByte('.')
				default:
					b.WriteString(regexp.QuoteMeta(string(c)))
				}
			}
			b.WriteString("$")
			pattern = b.String()
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid scope pattern: %w", err)
		}
		rules = append(rules, rule{raw: original, hostOnly: hostOnly, re: re})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("scope contains no rules")
	}
	return rules, nil
}

// Bare names are files, preserving missing-file errors. Prefix a literal
// wildcard filename with ./ to select the file form explicitly.
func inlineScope(arg string) bool {
	return strings.HasPrefix(arg, "regex:") || strings.HasPrefix(arg, "https://") ||
		strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "*://") ||
		(!strings.Contains(arg, "/") && strings.ContainsAny(arg, "*?"))
}

func loadScope(name string) (Scope, error) {
	if name == "" {
		return nil, fmt.Errorf("supply an explicit scope file with -s")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readScope(f)
}

func (rules Scope) match(e Endpoint) (string, bool) {
	for _, r := range rules {
		subject := e.URL
		if r.hostOnly {
			subject = e.Hostname
		}
		if r.re.MatchString(subject) {
			return r.raw, true
		}
	}
	return "no scope rule matched", false
}

func (rules Scope) split(all []Endpoint) (in, out []Endpoint) {
	for _, e := range all {
		if _, ok := rules.match(e); ok {
			in = append(in, e)
		} else {
			out = append(out, e)
		}
	}
	return
}
