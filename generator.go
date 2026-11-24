package main

import (
	"net/url"
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
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// generateFromInventory transfers a child route seen beneath one resource to
// sibling resources on the same origin. Only concrete, observed path segments
// are used. Cross-origin transfer is optional and always checked against scope.
func generateFromInventory(observed []Endpoint, scope Scope, cross bool, limit int) []Candidate {
	if limit == 0 {
		return nil
	}
	type route struct {
		endpoint Endpoint
		base     string
	}
	known := map[string]bool{}
	byOrigin := map[string][]Endpoint{}
	for _, e := range observed {
		if _, ok := scope.match(e); !ok {
			continue
		}
		known[routeKey(e)] = true
		byOrigin[e.Origin] = append(byOrigin[e.Origin], e)
	}
	profiles := analyze(observed)
	resources := map[string]Frequency{}
	for _, p := range profiles.Origins {
		resources[p.Origin] = p.Resources
	}
	var all []Candidate
	for origin, urls := range byOrigin {
		bases := map[string]map[string]route{}
		children := map[string]map[string]Endpoint{}
		for _, e := range urls {
			if len(e.Segments) == 0 || strings.HasSuffix(e.Path, "/") {
				continue
			}
			validRoute := true
			for _, part := range e.Segments {
				validRoute = validRoute && simpleRouteSegment.MatchString(part) && !dynamic(part)
			}
			if !validRoute {
				continue
			}
			escaped := strings.Split(strings.Trim(e.Path, "/"), "/")
			for i, segment := range e.Segments {
				base := "/" + strings.Join(escaped[:i+1], "/")
				parent := parentDir(base)
				if resources[origin][segment] == 0 || actions[strings.ToLower(segment)] || parent == "/" && !strings.HasSuffix(strings.ToLower(segment), "s") {
					continue
				}
				if bases[parent] == nil {
					bases[parent] = map[string]route{}
				}
				if _, exists := bases[parent][base]; !exists {
					bases[parent][base] = route{e, base}
				}
			}
			last := e.Segments[len(e.Segments)-1]
			parent := parentDir(e.Path)
			if children[parent] == nil {
				children[parent] = map[string]Endpoint{}
			}
			children[parent][last] = e
		}
		for _, siblingMap := range bases {
			if len(siblingMap) < 2 || len(siblingMap) > 64 {
				continue
			}
			siblings := make([]route, 0, len(siblingMap))
			for _, item := range siblingMap {
				siblings = append(siblings, item)
			}
			childCounts := map[string]int{}
			safeChildCounts := map[string]int{}
			for _, source := range siblings {
				for child := range children[source.base] {
					if simpleRouteSegment.MatchString(child) && !dynamic(child) && !unsafeRouteSuffix(child) {
						childCounts[child]++
						safeChildCounts[source.base]++
					}
				}
			}
			for _, source := range siblings {
				if serviceRoutes[strings.ToLower(path.Base(source.base))] {
					continue
				}
				for child, evidence := range children[source.base] {
					if !simpleRouteSegment.MatchString(child) || dynamic(child) {
						continue
					}
					lower := strings.ToLower(child)
					if unsafeRouteSuffix(child) {
						continue
					}
					richSource := safeChildCounts[source.base] >= 2 && strings.HasSuffix(strings.ToLower(path.Base(source.base)), "s")
					if !readActions[lower] && childCounts[child] < 2 && !richSource {
						continue
					}
					for _, target := range siblings {
						if target.base == source.base || strings.EqualFold(path.Base(target.base), child) {
							continue
						}
						targetName := path.Base(target.base)
						if serviceRoutes[strings.ToLower(targetName)] || !strings.HasSuffix(strings.ToLower(targetName), "s") && len(children[target.base]) == 0 && resources[origin][targetName] < 2 {
							continue
						}
						if !readActions[lower] && childCounts[child] < 2 && !strings.HasSuffix(strings.ToLower(targetName), "s") {
							continue
						}
						proposed, err := normalize(target.endpoint.Origin + target.base + "/" + url.PathEscape(child))
						if err != nil || known[routeKey(proposed)] {
							continue
						}
						if _, ok := scope.match(proposed); !ok {
							continue
						}
						score := 40 + min(childCounts[child], 3)*5
						reason := "child route observed on a sibling resource on this origin"
						if readActions[lower] {
							score += 30
						} else if childCounts[child] >= 2 {
							score += 10
							reason = "same child route observed under multiple sibling resources"
						} else {
							reason = "application term observed under a resource with multiple child routes"
						}
						all = append(all, Candidate{URL: proposed.URL, Hostname: proposed.Hostname, Path: proposed.Path, Method: "GET", SourcePattern: target.base + "/{observed-child}", Evidence: []string{target.endpoint.URL, evidence.URL}, Reason: reason, Score: score})
					}
				}
			}
		}
	}
	if cross {
		// Transfer only concrete paths already observed elsewhere, and only to
		// origins present in the authorized inventory.
		for origin, urls := range byOrigin {
			if len(urls) == 0 {
				continue
			}
			for sourceOrigin, sourceURLs := range byOrigin {
				if sourceOrigin == origin {
					continue
				}
				for _, source := range sourceURLs {
					if len(source.Segments) == 0 || unsafeRouteSuffix(source.Segments[len(source.Segments)-1]) {
						continue
					}
					validRoute := true
					for _, part := range source.Segments {
						validRoute = validRoute && simpleRouteSegment.MatchString(part) && !dynamic(part)
					}
					if !validRoute {
						continue
					}
					proposed, err := normalize(origin + source.Path)
					if err != nil || known[routeKey(proposed)] {
						continue
					}
					if _, ok := scope.match(proposed); !ok {
						continue
					}
					all = append(all, Candidate{URL: proposed.URL, Hostname: proposed.Hostname, Path: proposed.Path, Method: "GET", SourcePattern: source.Path, Evidence: []string{source.URL, urls[0].URL}, Reason: "path observed on another authorized origin", Score: 45})
				}
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		return all[i].URL < all[j].URL
	})
	unique := make([]Candidate, 0, min(limit, len(all)))
	seen := map[string]bool{}
	for _, c := range all {
		if !seen[c.URL] {
			seen[c.URL] = true
			unique = append(unique, c)
			if len(unique) == limit {
				break
			}
		}
	}
	return unique
}
