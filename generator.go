package main

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

type Candidate struct {
	URL           string
	Hostname      string
	Path          string
	Method        string
	SourcePattern string
	Evidence      []string
	Reason        string
	Score         int
}

var readActions = stringSet("details health history list pending preferences preview profile search settings status")
var stateChangeActions = stringSet("activate add affiliate apply approve archive cancel cancellation charge checkout create deactivate delete deny disable disaffiliate edit enable export import login logout new pay place process purchase remove reset send submit swap update")
var serviceRoutes = stringSet("actuator api-docs graphql openapi swagger")
var simpleRouteSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func unsafeRouteSuffix(segment string) bool {
	parts := strings.FieldsFunc(strings.ToLower(segment), func(r rune) bool { return r == '-' || r == '_' })
	return len(parts) > 0 && stateChangeActions[parts[0]]
}

func parentDir(p string) string {
	if p == "/" {
		return "/"
	}
	return path.Dir(strings.TrimSuffix(p, "/"))
}
func routeKey(e Endpoint) string { return e.Origin + e.Path }

// The manifest is the authoritative set of concrete routes. Other origins
// can contribute ranking evidence only for routes declared on the target.
func generate(observed, manifest []Endpoint, scope Scope, cross bool, limit int) []Candidate {
	known := map[string]bool{}
	sibling := map[string]string{}
	pathSource := map[string]Endpoint{}
	for _, e := range observed {
		if _, ok := scope.match(e); !ok {
			continue
		}
		known[routeKey(e)] = true
		dir := e.Origin + parentDir(e.Path)
		if _, ok := sibling[dir]; !ok {
			sibling[dir] = e.URL
		}
		if _, ok := pathSource[e.Path]; !ok {
			pathSource[e.Path] = e
		}
	}
	out := []Candidate{}
	for _, e := range manifest {
		if _, ok := scope.match(e); !ok || known[routeKey(e)] {
			continue
		}
		known[routeKey(e)] = true
		dir := parentDir(e.Path)
		c := Candidate{
			URL: e.URL, Hostname: e.Hostname, Path: e.Path, Method: "GET",
			SourcePattern: path.Join(dir, "{route}"),
			Evidence:      []string{e.Original},
			Reason:        "declared in route manifest, absent from observed paths",
			Score:         50,
		}
		if neighbor := sibling[e.Origin+dir]; neighbor != "" {
			c.Evidence = append(c.Evidence, neighbor)
			c.Score += 30
			c.Reason += "; observed sibling on this origin"
		}
		if source, ok := pathSource[e.Path]; cross && ok && source.Origin != e.Origin {
			c.Evidence = append(c.Evidence, source.URL)
			c.Score += 15
			c.Reason += "; same path observed on another in-scope origin"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].URL < out[j].URL
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
