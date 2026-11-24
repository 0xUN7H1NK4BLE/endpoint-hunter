package main

import "testing"

func TestGenerator(t *testing.T) {
	s := scopeFor(t, "a.test\nb.test")
	a, b := "https://a.test/api/", "https://b.test/api/"
	observed := []Endpoint{entry(t, a+"items"), entry(t, b+"books?q=1")}
	manifest := []Endpoint{entry(t, b+"items"), entry(t, b+"items?q=x"), entry(t, b+"books"), entry(t, b+"reading-lists"), entry(t, "https://c.test/api/items")}
	local := generate(observed, manifest, s, false, 10)
	cross := generate(observed, manifest, s, true, 1)
	if len(local) != 2 || local[0].Score != 80 || len(cross) != 1 || cross[0].URL != b+"items" || len(cross[0].Evidence) != 3 || cross[0].Score <= local[0].Score {
		t.Fatal(local, cross)
	}
	if got := generate(observed, nil, s, true, 10); len(got) != 0 {
		t.Fatal(got)
	}
	if got := generate(observed, manifest, s, true, 0); len(got) != 2 {
		t.Fatal(got)
	}
}

func TestGenerateWithOriginScope(t *testing.T) {
	base := "https://app.example.test/api/v1/"
	observed := []Endpoint{
		entry(t, base+"users"),
		entry(t, base+"orders"),
		entry(t, base+"users/search"),
		entry(t, "https://api.example.test/api/v1/users/search"),
	}
	s := scopeFor(t, "https://app.example.test")
	got := generateFromInventory(observed, s, false, 10)
	if len(got) != 1 || got[0].URL != base+"orders/search" {
		t.Fatalf("origin scope did not generate expected route: %+v", got)
	}
}

func TestGenerationUsesQueryOnlyPathsAndObservedVocabulary(t *testing.T) {
	base := "https://app.test/api/v1/"
	observed := []Endpoint{
		entry(t, base+"users?sort=recent"),
		entry(t, base+"orders?sort=recent"),
		entry(t, base+"users/directory?view=short"),
		entry(t, base+"users/profile?view=short"),
		entry(t, base+"users/delete"),
	}
	got := generateFromInventory(observed, scopeFor(t, "https://app.test"), false, 10)
	paths := map[string]bool{}
	for _, c := range got {
		paths[c.Path] = true
		if c.URL != "https://app.test"+c.Path || c.Path == "/api/v1/orders/delete" {
			t.Fatalf("unsafe or query-bearing candidate: %+v", c)
		}
	}
	if len(got) != 2 || !paths["/api/v1/orders/directory"] || !paths["/api/v1/orders/profile"] {
		t.Fatalf("missing application-specific candidates: %+v", got)
	}
}

func TestGenerationDoesNotTransferHex24IDs(t *testing.T) {
	base := "https://assessment.test/api/"
	observed := []Endpoint{
		entry(t, base+"assignments"),
		entry(t, base+"attachments"),
		entry(t, base+"assignments/62fa5bb3ecd4a00009dd4314"),
		entry(t, base+"assignments/605c9fbdcca70400082c9144"),
		entry(t, base+"assignments/search"),
	}
	got := generateFromInventory(observed, scopeFor(t, "https://assessment.test"), false, 100)
	if len(got) != 1 || got[0].URL != base+"attachments/search" {
		t.Fatalf("copied an object ID or missed the read route: %+v", got)
	}
}
