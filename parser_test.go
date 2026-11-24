package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func entry(t *testing.T, s string) Endpoint {
	t.Helper()
	e, err := normalize(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func fixture(t *testing.T, name, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestNormalize(t *testing.T) {
	raw := "HTTPS://APP.EXAMPLE.TEST.:443/a//old/%2e%2E/%62/a%2fb/?q=a%2Fb&q=2#detail"
	e := entry(t, raw)
	if e.URL != "https://app.example.test/a/b/a%2Fb/?q=a%2Fb&q=2" || e.Original != raw || e.Fragment != "detail" || e.Port != "" || len(e.Segments) != 3 || e.Segments[2] != "a/b" || len(e.Query["q"]) != 2 {
		t.Fatalf("%+v", e)
	}
	e = entry(t, "http://[::1]:08080/users")
	if e.Origin != "http://[::1]:8080" {
		t.Fatal(e)
	}
	for _, raw := range []string{"", "ftp://host/", "/a", "https://user@app.test/", "https://foo bar/", "https://app.test:65536/", "https://app.test:/", "https://app.test/%g0", "http://2001:db8::1/a", "http://[127.0.0.1]/"} {
		if _, err := normalize(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
func TestLoadInventory(t *testing.T) {
	base := "https://app.test/"
	data := "# x\n\n" + base + "r\n" + base + "r#x\n" + base + "r/\n" + base + "route.special\n" + base + "app.JS?x=2\nbad\n" + base + strings.Repeat("a", 70000)
	inv, err := loadInventory(fixture(t, "urls", data))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Counts != (Counts{7, 1, 1, 1, 4}) {
		t.Fatal(inv.Counts)
	}
}

func TestDynamicIdentifierShapes(t *testing.T) {
	for _, value := range []string{
		"12345",
		"550e8400-e29b-41d4-a716-446655440000",
		"62fa5bb3ecd4a00009dd4314",
		"62FA5BB3ECD4A00009DD4314",
	} {
		if !dynamic(value) {
			t.Errorf("did not recognize ID %q", value)
		}
	}
	for _, value := range []string{"assignments", "62fa5bb3ecd4a00009dd431", "62fa5bb3ecd4a00009dd431z"} {
		if dynamic(value) {
			t.Errorf("misclassified route word %q", value)
		}
	}
}
