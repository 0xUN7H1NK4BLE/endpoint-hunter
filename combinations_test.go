package main

import (
	"fmt"
	"strings"
	"testing"
)

func candidateURLs(items []Candidate) map[string]bool {
	urls := make(map[string]bool, len(items))
	for _, item := range items {
		urls[item.URL] = true
	}
	return urls
}

func TestGenerationEnumeratesLargeSiblingGroupAndReportsCap(t *testing.T) {
	base := "https://app.test/api/v1/"
	var observed []Endpoint
	for i := 0; i < 70; i++ {
		observed = append(observed, entry(t, fmt.Sprintf("%sresources%d", base, i)))
	}
	observed = append(observed, entry(t, base+"resources0/settings/privacy"))
	scope := scopeFor(t, "https://app.test/api/*")
	all, total := generateFromInventoryComplete(observed, scope, false, 0)
	if total < 69 || !candidateURLs(all)[base+"resources69/settings/privacy"] {
		t.Fatalf("large sibling family was truncated: total=%d", total)
	}
	limited, reported := generateFromInventoryComplete(observed, scope, false, 3)
	if len(limited) != 3 || reported != total {
		t.Fatalf("cap not reported: got=%d total=%d, want total=%d", len(limited), reported, total)
	}
	for _, item := range all {
		if len(item.Evidence) == 0 || item.Reason == "" || item.SourcePattern == "" {
			t.Fatalf("candidate lacks source evidence: %+v", item)
		}
	}
}

func TestGenerationKeepsIDsWithinExactResource(t *testing.T) {
	base := "https://app.test/api/"
	observed := []Endpoint{
		entry(t, base+"users/123"),
		entry(t, base+"users/456"),
		entry(t, base+"users/123/profile"),
		entry(t, base+"orders/789"),
		entry(t, base+"orders/999"),
	}
	got := candidateURLs(generateFromInventory(observed, scopeFor(t, "https://app.test"), false, 0))
	if !got[base+"users/456/profile"] {
		t.Fatal("same-resource ID combination missing")
	}
	for url := range got {
		if strings.Contains(url, "/orders/123") || strings.Contains(url, "/orders/456") ||
			strings.Contains(url, "/users/789") || strings.Contains(url, "/users/999") {
			t.Fatalf("ID crossed resource boundary: %s", url)
		}
	}
}

func TestGenerationCompletesDashedTwoPositionPattern(t *testing.T) {
	base := "https://app.test/api/v1/"
	observed := []Endpoint{
		entry(t, base+"order-history/list"),
		entry(t, base+"order-status/list"),
		entry(t, base+"product-history/list"),
	}
	got := candidateURLs(generateFromInventory(observed, scopeFor(t, "https://app.test/api/*"), false, 0))
	if !got[base+"product-status/list"] {
		t.Fatal("missing dashed pattern completion")
	}
}

func TestGenerationDoesNotCrossScopeOrOriginsByDefault(t *testing.T) {
	observed := []Endpoint{
		entry(t, "https://a.test/api/users"),
		entry(t, "https://a.test/api/orders"),
		entry(t, "https://a.test/api/users/search"),
		entry(t, "https://b.test/api/users"),
		entry(t, "https://c.test/api/users"),
	}
	scope := scopeFor(t, "a.test\nb.test")
	local := candidateURLs(generateFromInventory(observed, scope, false, 0))
	if !local["https://a.test/api/orders/search"] || local["https://b.test/api/orders/search"] {
		t.Fatalf("unexpected cross-origin transfer: %+v", local)
	}
	cross := candidateURLs(generateFromInventory(observed, scope, true, 0))
	if !cross["https://b.test/api/orders"] || cross["https://c.test/api/orders"] {
		t.Fatalf("cross-domain generation broke explicit scope: %+v", cross)
	}
}

func TestGenerationDoesNotTreatNamespacesOrOpaqueIDsAsVocabulary(t *testing.T) {
	base := "https://app.test/"
	observed := []Endpoint{
		entry(t, base+"api/cart"),
		entry(t, base+"app/cart"),
		entry(t, base+"api/orders"),
		entry(t, base+"app/profile"),
		entry(t, base+"api/profile"),
		entry(t, base+"api/resources/bkPqspTFSa8BuYqZA9936VjCe2bYJh2r"),
		entry(t, base+"api/orders/search"),
	}
	got := candidateURLs(generateFromInventory(observed, scopeFor(t, "https://app.test"), false, 0))
	for url := range got {
		if strings.Contains(url, "bkPqspTFSa8BuYqZA9936VjCe2bYJh2r") {
			t.Fatalf("opaque ID copied into candidate: %s", url)
		}
	}
	if got[base+"app/orders"] {
		t.Fatal("namespace permutation was treated as a resource pattern")
	}
	if !got[base+"api/resources/search"] {
		t.Fatal("ordinary resource combination unexpectedly removed")
	}
}
