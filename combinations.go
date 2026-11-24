package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// candidateCollector keeps one entry per concrete URL. The best-supported
// explanation wins when several observed route patterns propose the same URL.
type candidateCollector struct {
	scope Scope
	known map[string]bool
	items map[string]Candidate
}

func (c *candidateCollector) add(origin, proposedPath, pattern, reason string, score int, evidence ...string) {
	e, err := normalize(origin + proposedPath)
	if err != nil || c.known[routeKey(e)] {
		return
	}
	if _, ok := c.scope.match(e); !ok {
		return
	}
	item := Candidate{
		URL: e.URL, Hostname: e.Hostname, Path: e.Path, Method: "GET",
		SourcePattern: pattern, Reason: reason, Score: score, Evidence: evidence,
	}
	if old, exists := c.items[e.URL]; !exists || item.Score > old.Score ||
		item.Score == old.Score && len(item.Evidence) > len(old.Evidence) {
		c.items[e.URL] = item
	}
}

func (c *candidateCollector) result(limit int) ([]Candidate, int) {
	all := make([]Candidate, 0, len(c.items))
	for _, item := range c.items {
		all = append(all, item)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		return all[i].URL < all[j].URL
	})
	total := len(all)
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, total
}

func safeStaticParts(parts []string) bool {
	for _, part := range parts {
		if !simpleRouteSegment.MatchString(part) || dynamic(part) || opaqueIdentifier(part) || unsafeRouteSuffix(part) {
			return false
		}
	}
	return true
}

// Many inventories contain path parameters that are neither numeric nor UUIDs.
// A long mixed-case alphanumeric value with digits is more likely an object
// token than endpoint vocabulary, so it must not spread to sibling routes.
func opaqueIdentifier(part string) bool {
	if len(part) < 20 {
		return false
	}
	upper, lower, digit := false, false, false
	for _, c := range part {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

type resourceBase struct {
	path     string
	evidence Endpoint
}

type resourceFamily struct {
	bases map[string]resourceBase
	tails map[string]map[string]Endpoint
}

// collectSiblingCombinations fills every missing resource × observed suffix
// cell within one origin and parent. Suffixes can span multiple path segments.
func collectSiblingCombinations(urls []Endpoint, resources Frequency, out *candidateCollector) {
	families := map[string]*resourceFamily{}
	for _, e := range urls {
		if len(e.Segments) == 0 {
			continue
		}
		safeAll := safeStaticParts(e.Segments)
		escaped := strings.Split(strings.Trim(e.Path, "/"), "/")
		for i, segment := range e.Segments {
			if !safeStaticParts([]string{segment}) {
				break
			}
			if resources[segment] == 0 || actions[strings.ToLower(segment)] ||
				serviceRoutes[strings.ToLower(segment)] {
				continue
			}
			base := "/" + strings.Join(escaped[:i+1], "/")
			parent := parentDir(base)
			family := families[parent]
			if family == nil {
				family = &resourceFamily{bases: map[string]resourceBase{}, tails: map[string]map[string]Endpoint{}}
				families[parent] = family
			}
			current, exists := family.bases[base]
			if !exists || len(e.Query) == 0 && len(current.evidence.Query) > 0 {
				family.bases[base] = resourceBase{path: base, evidence: e}
			}
			if i+1 == len(escaped) || !safeAll {
				continue
			}
			tail := strings.Join(escaped[i+1:], "/")
			if strings.HasSuffix(e.Path, "/") {
				tail += "/"
			}
			if family.tails[base] == nil {
				family.tails[base] = map[string]Endpoint{}
			}
			old, exists := family.tails[base][tail]
			if !exists || len(e.Query) == 0 && len(old.Query) > 0 {
				family.tails[base][tail] = e
			}
		}
	}
	for _, parent := range sortedKeys(families) {
		family := families[parent]
		if len(family.bases) < 2 {
			continue
		}
		baseNames := sortedKeys(family.bases)
		tailSources := map[string][]Endpoint{}
		for _, base := range baseNames {
			for _, tail := range sortedKeys(family.tails[base]) {
				tailSources[tail] = append(tailSources[tail], family.tails[base][tail])
			}
		}
		for _, tail := range sortedKeys(tailSources) {
			sources := tailSources[tail]
			first := strings.Split(strings.TrimSuffix(tail, "/"), "/")[0]
			for _, base := range baseNames {
				if _, exists := family.tails[base][tail]; exists ||
					strings.EqualFold(strings.TrimPrefix(base, parent+"/"), first) {
					continue
				}
				target := family.bases[base]
				evidence := []string{target.evidence.URL}
				for _, source := range sources {
					if len(evidence) == 4 {
						break
					}
					evidence = append(evidence, source.URL)
				}
				score := 45 + min(len(sources), 3)*7
				if readActions[strings.ToLower(first)] {
					score += 15
				}
				if strings.Count(tail, "/") > 0 {
					score -= min(10, strings.Count(tail, "/")*3)
				}
				out.add(target.evidence.Origin, base+"/"+tail, base+"/{observed-suffix}",
					fmt.Sprintf("suffix observed under %d sibling resource(s)", len(sources)), score, evidence...)
			}
		}
	}
}

type idResource struct {
	origin   string
	path     string
	id       string
	evidence Endpoint
	tails    map[string]Endpoint
}

// collectIDCombinations proposes a missing route template once per resource.
// A suffix already observed under /resource/{id} is known route structure;
// testing that suffix against every other ID would only repeat the same route.
// IDs remain attached to the resource where they were seen.
func collectIDCombinations(urls []Endpoint, out *candidateCollector) {
	families := map[string]map[string]*idResource{}
	for _, e := range urls {
		idAt := -1
		for i, part := range e.Segments {
			if dynamic(part) || opaqueIdentifier(part) {
				if idAt >= 0 {
					idAt = -2
					break
				}
				idAt = i
			}
		}
		if idAt <= 0 || !safeStaticParts(e.Segments[:idAt]) ||
			!safeStaticParts(e.Segments[idAt+1:]) {
			continue
		}
		escaped := strings.Split(strings.Trim(e.Path, "/"), "/")
		resourcePath := "/" + strings.Join(escaped[:idAt], "/")
		resourceKey := strings.ToLower(resourcePath)
		familyKey := e.Origin + " " + parentDir(resourceKey)
		family := families[familyKey]
		if family == nil {
			family = map[string]*idResource{}
			families[familyKey] = family
		}
		resource := family[resourceKey]
		if resource == nil {
			resource = &idResource{origin: e.Origin, path: resourcePath, id: escaped[idAt], evidence: e, tails: map[string]Endpoint{}}
			family[resourceKey] = resource
		} else if resource.path != resourceKey && resourcePath == resourceKey {
			// Prefer the lowercase spelling when the inventory contains both
			// case variants of one resource template.
			resource.path, resource.id, resource.evidence = resourcePath, escaped[idAt], e
		}
		if idAt+1 < len(escaped) {
			tail := strings.Join(escaped[idAt+1:], "/")
			if strings.HasSuffix(e.Path, "/") {
				tail += "/"
			}
			if _, exists := resource.tails[tail]; !exists {
				resource.tails[tail] = e
			}
		}
	}
	for _, key := range sortedKeys(families) {
		family := families[key]
		if len(family) < 2 {
			continue
		}
		resources := sortedKeys(family)
		tailSources := map[string][]Endpoint{}
		for _, resourcePath := range resources {
			for _, tail := range sortedKeys(family[resourcePath].tails) {
				tailSources[tail] = append(tailSources[tail], family[resourcePath].tails[tail])
			}
		}
		for _, tail := range sortedKeys(tailSources) {
			sources := tailSources[tail]
			for _, resourcePath := range resources {
				target := family[resourcePath]
				if _, known := target.tails[tail]; known {
					continue
				}
				out.add(target.origin, target.path+"/"+target.id+"/"+tail,
					target.path+"/{id}/"+tail, "new ID route suffix observed under sibling resource",
					60+min(len(sources), 3)*5, target.evidence.URL, sources[0].URL)
			}
		}
	}
}

// A routeShape splits hyphenated segments into separate coordinates while
// keeping the part counts needed to reconstruct a valid concrete path.
type routeShape struct {
	counts   []int
	trailing bool
}

func (s routeShape) key() string {
	var b strings.Builder
	for _, count := range s.counts {
		b.WriteString(strconv.Itoa(count))
		b.WriteByte(',')
	}
	if s.trailing {
		b.WriteByte('/')
	}
	return b.String()
}

func (s routeShape) render(tokens []string) string {
	segments := make([]string, len(s.counts))
	at := 0
	for i, count := range s.counts {
		segments[i] = strings.Join(tokens[at:at+count], "-")
		at += count
	}
	result := "/" + strings.Join(segments, "/")
	if s.trailing {
		result += "/"
	}
	return result
}

type shapedRoute struct {
	shape    routeShape
	tokens   []string
	endpoint Endpoint
	freq     int64
	groups   []*variationGroup
}

type variation struct {
	freq     int64
	endpoint Endpoint
}

type variationGroup struct {
	values map[string]variation
}

func (g *variationGroup) routeVocabulary() bool {
	seen := map[string]bool{}
	for value := range g.values {
		lower := strings.ToLower(value)
		if namespaces[lower] || opaqueIdentifier(value) || seen[lower] {
			return false
		}
		seen[lower] = true
	}
	return true
}

// S² - sum(f²) counts ordered pairs with different values without iterating
// over those pairs.
func (g *variationGroup) pairWeight() int64 {
	var sum, squares int64
	for _, v := range g.values {
		sum += v.freq
		squares += v.freq * v.freq
	}
	return sum*sum - squares
}

func shapeOf(e Endpoint) (routeShape, []string, bool) {
	if len(e.Segments) < 2 || !safeStaticParts(e.Segments) {
		return routeShape{}, nil, false
	}
	shape := routeShape{trailing: strings.HasSuffix(e.Path, "/")}
	var tokens []string
	for _, segment := range e.Segments {
		parts := strings.Split(segment, "-")
		for _, part := range parts {
			if part == "" {
				return routeShape{}, nil, false
			}
		}
		shape.counts = append(shape.counts, len(parts))
		tokens = append(tokens, parts...)
	}
	return shape, tokens, true
}

func variationKey(shapeKey string, tokens []string, at int) string {
	var b strings.Builder
	b.WriteString(shapeKey)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(at))
	b.WriteByte(0)
	for i, token := range tokens {
		if i != at {
			b.WriteString(token)
		}
		b.WriteByte(0)
	}
	return b.String()
}

// collectRectangles completes three-corner patterns. Two one-coordinate
// variations of an observed route support the missing fourth combination.
// A coordinate may be a whole path segment or one part of a dashed segment.
func collectRectangles(urls []Endpoint, out *candidateCollector) {
	byPath := map[string]*shapedRoute{}
	for _, e := range urls {
		shape, tokens, ok := shapeOf(e)
		if !ok {
			continue
		}
		route := byPath[e.Path]
		if route == nil {
			route = &shapedRoute{shape: shape, tokens: tokens, endpoint: e}
			byPath[e.Path] = route
		}
		route.freq++
		if len(e.Query) == 0 {
			route.endpoint = e
		}
	}
	groups := map[string]*variationGroup{}
	for _, path := range sortedKeys(byPath) {
		route := byPath[path]
		route.groups = make([]*variationGroup, len(route.tokens))
		for at, token := range route.tokens {
			key := variationKey(route.shape.key(), route.tokens, at)
			group := groups[key]
			if group == nil {
				group = &variationGroup{values: map[string]variation{}}
				groups[key] = group
			}
			group.values[token] = variation{freq: route.freq, endpoint: route.endpoint}
			route.groups[at] = group
		}
	}
	for _, path := range sortedKeys(byPath) {
		route := byPath[path]
		for i := 0; i < len(route.tokens); i++ {
			left := route.groups[i]
			if len(left.values) < 2 || !left.routeVocabulary() {
				continue
			}
			for j := i + 1; j < len(route.tokens); j++ {
				right := route.groups[j]
				if len(right.values) < 2 || !right.routeVocabulary() {
					continue
				}
				support := min(left.pairWeight(), right.pairWeight())
				bonus := 0
				for support > 1 && bonus < 15 {
					support /= 2
					bonus += 3
				}
				for _, leftValue := range sortedKeys(left.values) {
					if leftValue == route.tokens[i] {
						continue
					}
					for _, rightValue := range sortedKeys(right.values) {
						if rightValue == route.tokens[j] {
							continue
						}
						candidateTokens := append([]string(nil), route.tokens...)
						candidateTokens[i], candidateTokens[j] = leftValue, rightValue
						path := route.shape.render(candidateTokens)
						proposed, err := normalize(route.endpoint.Origin + path)
						if err != nil || !safeStaticParts(proposed.Segments) {
							continue
						}
						pattern := append([]string(nil), route.tokens...)
						pattern[i], pattern[j] = "{variant}", "{variant}"
						out.add(route.endpoint.Origin, path, route.shape.render(pattern),
							"three observed routes complete a two-position pattern", 80+bonus,
							route.endpoint.URL, left.values[leftValue].endpoint.URL, right.values[rightValue].endpoint.URL)
					}
				}
			}
		}
	}
}

func hostFamilyScore(a, b string) int {
	if a == b {
		return 20
	}
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	if len(left) != len(right) {
		return 0
	}
	differ := -1
	for i := range left {
		if left[i] != right[i] {
			if differ >= 0 {
				return 0
			}
			differ = i
		}
	}
	if differ < 0 {
		return 0
	}
	lparts, rparts := strings.Split(left[differ], "-"), strings.Split(right[differ], "-")
	if len(lparts) > 1 && len(lparts) == len(rparts) {
		dashDiff := 0
		for i := range lparts {
			if lparts[i] != rparts[i] {
				dashDiff++
			}
		}
		if dashDiff == 1 {
			return 15
		}
	}
	return 8
}

func generateFromInventoryComplete(observed []Endpoint, scope Scope, cross bool, limit int) ([]Candidate, int) {
	byOrigin := map[string][]Endpoint{}
	known := map[string]bool{}
	for _, e := range observed {
		if _, ok := scope.match(e); !ok {
			continue
		}
		known[routeKey(e)] = true
		byOrigin[e.Origin] = append(byOrigin[e.Origin], e)
	}
	out := &candidateCollector{scope: scope, known: known, items: map[string]Candidate{}}
	profiles := analyze(observed)
	resources := map[string]Frequency{}
	for _, profile := range profiles.Origins {
		resources[profile.Origin] = profile.Resources
	}
	origins := sortedKeys(byOrigin)
	for _, origin := range origins {
		urls := byOrigin[origin]
		collectSiblingCombinations(urls, resources[origin], out)
		collectIDCombinations(urls, out)
		collectRectangles(urls, out)
	}
	if cross {
		for _, targetOrigin := range origins {
			targetURLs := byOrigin[targetOrigin]
			for _, sourceOrigin := range origins {
				if targetOrigin == sourceOrigin {
					continue
				}
				for _, source := range byOrigin[sourceOrigin] {
					if len(source.Segments) == 0 || !safeStaticParts(source.Segments) {
						continue
					}
					out.add(targetOrigin, source.Path, source.Path,
						"path observed on another authorized origin", 35+hostFamilyScore(targetURLs[0].Hostname, source.Hostname),
						targetURLs[0].URL, source.URL)
				}
			}
		}
	}
	return out.result(limit)
}

// Keep the original API for focused generator tests and callers that only
// need the candidate list. The CLI uses the total to report truncation.
func generateFromInventory(observed []Endpoint, scope Scope, cross bool, limit int) []Candidate {
	items, _ := generateFromInventoryComplete(observed, scope, cross, limit)
	return items
}
