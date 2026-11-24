package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// statusExclusions is a repeatable flag whose values are comma-separated HTTP
// status codes. Filtering happens after requests so every candidate is tested.
type statusExclusions map[int]bool

func (excluded *statusExclusions) String() string {
	if len(*excluded) == 0 {
		return ""
	}
	codes := make([]int, 0, len(*excluded))
	for code := range *excluded {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	parts := make([]string, len(codes))
	for i, code := range codes {
		parts[i] = strconv.Itoa(code)
	}
	return strings.Join(parts, ",")
}

func (excluded *statusExclusions) Set(raw string) error {
	var parsed []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		code, err := strconv.Atoi(part)
		if part == "" || err != nil || code < 100 || code > 599 {
			return fmt.Errorf("-es expects comma-separated HTTP status codes from 100 to 599")
		}
		parsed = append(parsed, code)
	}
	if *excluded == nil {
		*excluded = make(statusExclusions)
	}
	for _, code := range parsed {
		(*excluded)[code] = true
	}
	return nil
}

func (excluded statusExclusions) has(code int) bool { return excluded[code] }

func (excluded statusExclusions) filter(rows []Result) []Result {
	visible := make([]Result, 0, len(rows))
	for _, row := range rows {
		if !excluded.has(row.Status) {
			visible = append(visible, row)
		}
	}
	return visible
}
