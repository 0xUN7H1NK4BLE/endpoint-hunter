package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// A template describes the part of a route starting with its first resource.
// Application prefixes, literal names and identifier values are omitted.
type TemplateSuggestion struct {
	Origin       string
	Template     string
	Parent       string
	ParentCount  int
	Analogy      string
	AnalogyCount int
}

func resourceShapes(patterns Frequency) Frequency {
	shapes := Frequency{}
	for pattern, count := range patterns {
		parts := strings.Split(strings.Trim(pattern, "/"), "/")
		first := 0
		for first < len(parts) && parts[first] != "{resource}" {
			first++
		}
		tail := parts[first:]
		if len(tail) == 0 || len(tail) > 6 {
			continue
		}
		recognized := true
		for _, token := range tail {
			if token != "{resource}" && token != "{id}" && token != "{action}" {
				recognized = false
				break
			}
		}
		if recognized {
			shapes["/"+strings.Join(tail, "/")] += count
		}
	}
	return shapes
}

func inferTemplates(a Analysis, limit int) []TemplateSuggestion {
	var suggestions []TemplateSuggestion
	for _, profile := range a.Origins {
		shapes := resourceShapes(profile.Patterns)
		for parent, count := range shapes {
			if strings.Count(parent, "/") >= 6 {
				continue
			}
			for _, suffix := range []string{"/{id}", "/{action}"} {
				analogy := "/{resource}" + suffix
				candidate := parent + suffix
				if shapes[analogy] == 0 || shapes[candidate] > 0 {
					continue
				}
				// Resources can have identifier and action children. Instance
				// actions also combine an observed ID route with an action route.
				lastIsResource := strings.HasSuffix(parent, "/{resource}")
				instanceAction := strings.HasSuffix(parent, "/{id}") && suffix == "/{action}"
				if !lastIsResource && !instanceAction {
					continue
				}
				suggestions = append(suggestions, TemplateSuggestion{
					Origin: profile.Origin, Template: candidate, Parent: parent, ParentCount: count,
					Analogy: analogy, AnalogyCount: shapes[analogy],
				})
			}
		}
	}
	// A common parent cannot compensate for an analogy seen only once.
	sort.Slice(suggestions, func(i, j int) bool {
		a, b := suggestions[i], suggestions[j]
		as, bs := min(a.ParentCount, a.AnalogyCount), min(b.ParentCount, b.AnalogyCount)
		if as != bs {
			return as > bs
		}
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		return a.Template < b.Template
	})
	if limit > 0 && len(suggestions) > limit {
		return suggestions[:limit]
	}
	return suggestions
}

func writeTemplates(w io.Writer, suggestions []TemplateSuggestion) error {
	for _, s := range suggestions {
		_, err := fmt.Fprintf(w, "%s  %s\n  Observed on this origin: %s (%d paths) and %s (%d paths)\n", s.Origin, s.Template, s.Parent, s.ParentCount, s.Analogy, s.AnalogyCount)
		if err != nil {
			return err
		}
	}
	return nil
}
