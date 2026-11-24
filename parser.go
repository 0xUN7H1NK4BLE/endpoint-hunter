package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const maxLine = 2 << 20

type Endpoint struct {
	Original string
	URL      string
	Origin   string
	Scheme   string
	Hostname string
	Port     string
	Path     string   // Escaped, normalized path used as the route identity.
	Segments []string // Decoded separately to preserve encoded slash boundaries.
	Query    url.Values
	Fragment string
}
type Counts struct{ Lines, Invalid, Assets, Duplicates, Unique int }
type Inventory struct {
	URLs     []Endpoint
	Counts   Counts
	Warnings []string
}

var assets = stringSet(".js .css .png .jpg .jpeg .gif .svg .ico .woff .woff2 .ttf .eot .map .pdf .webp")
var uuid = regexp.MustCompile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
var hex24ID = regexp.MustCompile("(?i)^[0-9a-f]{24}$")
var numeric = regexp.MustCompile("^[0-9]+$")
var dnsLabel = regexp.MustCompile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

func stringSet(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}
func dynamic(s string) bool {
	return numeric.MatchString(s) || uuid.MatchString(s) || hex24ID.MatchString(s)
}

func normalize(raw string) (Endpoint, error) {
	var e Endpoint
	if strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return e, fmt.Errorf("unescaped whitespace or control character")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return e, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
		return e, fmt.Errorf("expected an absolute HTTP(S) URL without userinfo")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if strings.Count(u.Host, ":") > 1 && !strings.HasPrefix(u.Host, "[") {
		return e, fmt.Errorf("IPv6 addresses require brackets")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if strings.ContainsAny(u.Host, "[]") || len(host) > 253 {
			return e, fmt.Errorf("invalid hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if !dnsLabel.MatchString(label) {
				return e, fmt.Errorf("invalid hostname")
			}
		}
	} else {
		if strings.HasPrefix(u.Host, "[") && !strings.Contains(host, ":") {
			return e, fmt.Errorf("brackets require IPv6")
		}
		host = ip.String()
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return e, fmt.Errorf("empty port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return e, fmt.Errorf("invalid port")
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	p := canonicalEscapes(u.EscapedPath())
	trailing := strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..")
	p = path.Clean("/" + p)
	if p != "/" && trailing {
		p += "/"
	}
	origin := u.Scheme + "://" + authority
	normalized := origin + p
	if u.RawQuery != "" || u.ForceQuery {
		normalized += "?" + u.RawQuery
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return e, fmt.Errorf("invalid query: %w", err)
	}
	var segments []string
	if inner := strings.Trim(p, "/"); inner != "" {
		for _, s := range strings.Split(inner, "/") {
			decoded, _ := url.PathUnescape(s)
			segments = append(segments, decoded)
		}
	}
	return Endpoint{raw, normalized, origin, u.Scheme, host, port, p, segments, q, u.Fragment}, nil
}

// EscapedPath supplies valid escapes. Decode only RFC 3986 unreserved bytes.
func canonicalEscapes(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			b.WriteByte(p[i])
			continue
		}
		hex := p[i+1 : i+3]
		n, _ := strconv.ParseUint(hex, 16, 8)
		c := byte(n)
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c)) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(hex))
		}
		i += 2
	}
	return b.String()
}

func readLines(r io.Reader, visit func(int, string) error) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), maxLine)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := visit(n, line); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
	}
	return s.Err()
}

func loadInventory(name string) (Inventory, error) {
	var inv Inventory
	f, err := os.Open(name)
	if err != nil {
		return inv, err
	}
	defer f.Close()
	seen := map[string]bool{}
	err = readLines(f, func(n int, line string) error {
		inv.Counts.Lines++
		e, err := normalize(line)
		if err != nil {
			inv.Counts.Invalid++
			if len(inv.Warnings) < 5 {
				inv.Warnings = append(inv.Warnings, fmt.Sprintf("line %d: invalid URL", n))
			}
			return nil
		}
		if len(e.Segments) > 0 && assets[strings.ToLower(path.Ext(e.Segments[len(e.Segments)-1]))] {
			inv.Counts.Assets++
			return nil
		}
		if seen[e.URL] {
			inv.Counts.Duplicates++
			return nil
		}
		seen[e.URL] = true
		inv.URLs = append(inv.URLs, e)
		return nil
	})
	sort.Slice(inv.URLs, func(i, j int) bool { return inv.URLs[i].URL < inv.URLs[j].URL })
	inv.Counts.Unique = len(inv.URLs)
	return inv, err
}
