package main

import (
	"regexp"
	"sort"
	"strings"
)

var versions = regexp.MustCompile("(?i)^v[0-9]+$")
var actions = stringSet("add archive cancel checkout create delete details edit export health history import list login logout new pending preferences preview profile remove search settings status submit update")
var namespaces = stringSet("api app graphql rest rpc")
var snake = regexp.MustCompile("^[a-z0-9]+(_[a-z0-9]+)+$")
var kebab = regexp.MustCompile("^[a-z0-9]+(-[a-z0-9]+)+$")
var camel = regexp.MustCompile("^[a-z][a-z0-9]*[A-Z][a-zA-Z0-9]*$")

type Frequency map[string]int
type Profile struct {
	Hostname         string
	Origin           string
	CommonPrefixes   Frequency
	ApplicationBases Frequency
	APIPrefixes      Frequency
	Versions         Frequency
	Resources        Frequency
	Actions          Frequency
	NestedResources  Frequency
	Identifiers      Frequency
	Conventions      Frequency
	Patterns         Frequency
	Vocabulary       Frequency
	QueryKeys        Frequency
}
type Analysis struct {
	Hostnames, Schemes, Ports []string
	Origins                   []*Profile
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func analyze(urls []Endpoint) Analysis {
	groups := map[string][]Endpoint{}
	hosts, schemes, ports := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range urls {
		hosts[e.Hostname] = true
		schemes[e.Scheme] = true
		port := e.Port
		if port == "" {
			if e.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		ports[port] = true
		groups[e.Origin] = append(groups[e.Origin], e)
	}
	a := Analysis{sortedKeys(hosts), sortedKeys(schemes), sortedKeys(ports), []*Profile{}}
	for _, origin := range sortedKeys(groups) {
		a.Origins = append(a.Origins, analyzeOrigin(groups[origin]))
	}
	return a
}
func analyzeOrigin(urls []Endpoint) *Profile {
	p := &Profile{
		Hostname: urls[0].Hostname, Origin: urls[0].Origin,
		CommonPrefixes: Frequency{}, ApplicationBases: Frequency{}, APIPrefixes: Frequency{},
		Versions: Frequency{}, Resources: Frequency{}, Actions: Frequency{},
		NestedResources: Frequency{}, Identifiers: Frequency{}, Conventions: Frequency{},
		Patterns: Frequency{}, Vocabulary: Frequency{}, QueryKeys: Frequency{},
	}
	seen := map[string]bool{}
	prefixes := Frequency{}
	for _, e := range urls {
		for key := range e.Query {
			p.QueryKeys[key]++
			p.Vocabulary[key]++
		}
		if seen[e.Path] {
			continue
		}
		seen[e.Path] = true
		parts := e.Segments
		escaped := strings.Split(strings.Trim(e.Path, "/"), "/")
		// Bound prefix statistics for unusually deep paths. Full-route patterns
		// and vocabulary still cover every segment.
		depth := min(len(parts), 64)
		prefixesAtDepth := make([]string, depth)
		end := 1
		for i := range prefixesAtDepth {
			end += len(escaped[i])
			if end < len(e.Path) {
				end++
				prefixesAtDepth[i] = e.Path[:end]
			} else {
				prefixesAtDepth[i] = e.Path + "/"
			}
		}
		base := 0
		for i, s := range parts {
			lower := strings.ToLower(s)
			if i < depth && (namespaces[lower] || versions.MatchString(s)) {
				base = i + 1
				prefix := prefixesAtDepth[i]
				if lower != "app" {
					p.APIPrefixes[prefix]++
				}
				if versions.MatchString(s) {
					p.Versions[s]++
				}
			}
		}
		if base > 0 {
			p.ApplicationBases[prefixesAtDepth[base-1]]++
		}
		pattern := append([]string(nil), escaped...)
		previousResource := ""
		for i, s := range parts {
			if i < depth && i < len(parts)-1 {
				prefixes[prefixesAtDepth[i]]++
			}
			if dynamic(s) {
				kind := "numeric"
				if uuid.MatchString(s) {
					kind = "uuid"
				} else if hex24ID.MatchString(s) && !numeric.MatchString(s) {
					kind = "hex24"
				}
				p.Identifiers[kind]++
				pattern[i] = "{id}"
				continue
			}
			p.Vocabulary[s]++
			switch {
			case snake.MatchString(s):
				p.Conventions["snake_case"]++
			case kebab.MatchString(s):
				p.Conventions["kebab-case"]++
			case camel.MatchString(s):
				p.Conventions["camelCase"]++
			}
			if i < base {
				continue
			}
			lower := strings.ToLower(s)
			leadsToDetail := i+1 < len(parts) && (dynamic(parts[i+1]) || actions[strings.ToLower(parts[i+1])])
			switch {
			case i == len(parts)-1 && actions[lower]:
				p.Actions[s]++
				pattern[i] = "{action}"
			case strings.HasSuffix(lower, "s") || leadsToDetail || (base > 0 && i == base):
				p.Resources[s]++
				pattern[i] = "{resource}"
				if previousResource != "" {
					p.NestedResources[previousResource+"/"+escaped[i]]++
				}
				previousResource = escaped[i]
			}
		}
		tmpl := "/" + strings.Join(pattern, "/")
		if e.Path != "/" && strings.HasSuffix(e.Path, "/") {
			tmpl += "/"
		}
		p.Patterns[tmpl]++
	}
	for k, n := range prefixes {
		if n >= 2 {
			p.CommonPrefixes[k] = n
		}
	}
	return p
}
