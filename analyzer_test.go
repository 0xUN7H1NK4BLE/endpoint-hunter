package main

import "testing"

func TestAnalyzer(t *testing.T) {
	base := "https://app.test/api/v1/"
	var urls []Endpoint
	for _, p := range []string{"books", "books/123", "books/550e8400-e29b-41d4-a716-446655440000", "books/62fa5bb3ecd4a00009dd4314", "books/search", "books/search?q=x", "reading-lists/books", "new_items", "longName"} {
		urls = append(urls, entry(t, base+p))
	}
	urls = append(urls, entry(t, "http://app.test:8080/app/users"))
	a := analyze(urls)
	if len(a.Hostnames) != 1 || len(a.Origins) != 2 || len(a.Ports) != 2 {
		t.Fatal(a)
	}
	p := a.Origins[1]
	if p.Patterns["/api/v1/{resource}/{id}"] != 3 || p.Actions["search"] != 1 || p.Identifiers["uuid"] != 1 || p.Identifiers["hex24"] != 1 || p.Resources["api"] != 0 || p.Vocabulary["123"] != 0 || p.Vocabulary["62fa5bb3ecd4a00009dd4314"] != 0 || p.QueryKeys["q"] != 1 || p.NestedResources["reading-lists/books"] != 1 || p.CommonPrefixes["/api/v1/books/"] != 4 || len(p.Conventions) != 3 {
		t.Fatalf("%+v", p)
	}
}
