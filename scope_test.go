package main

import (
	"strings"
	"testing"
)

func scopeFor(t *testing.T, s string) Scope {
	t.Helper()
	v, err := readScope(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestScope(t *testing.T) {
	s := scopeFor(t, "# scope\n*cat?log*\nhttps://*.example.test/tree/*\nregex:^https://api[0-9]+\\.test/v1(/.*)?$\nEXACT.TEST")
	for _, tc := range []struct{ url, rule string }{
		{"https://my-catalog.local/", "*cat?log*"}, {"https://other.test/?target=catalog", ""},
		{"https://a.example.test/tree/r?q=1", "https://*.example.test/tree/*"}, {"https://a.example.test/tree/%2E%2E/private", ""},
		{"https://api2.test/v1", "regex:^https://api[0-9]+\\.test/v1(/.*)?$"}, {"https://api2.test.evil/v1", ""},
		{"http://exact.test:8000/", "EXACT.TEST"}, {"https://other.test/?host=exact.test", ""},
	} {
		got, ok := s.match(entry(t, tc.url))
		if ok != (tc.rule != "") || ok && got != tc.rule {
			t.Errorf("%s: %s", tc.url, got)
		}
	}
}
func TestInvalidScope(t *testing.T) {
	for _, s := range []string{"", "\n# none", "good.test\nregex:[", "regex:", "missing.scheme/test"} {
		if rules, err := readScope(strings.NewReader(s)); err == nil || rules != nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := loadScope(""); err == nil {
		t.Fatal("missing scope accepted")
	}
}

func TestOriginScopeMatchesOnlyThatOrigin(t *testing.T) {
	s := scopeFor(t, "https://APP.EXAMPLE.TEST:443")
	for _, raw := range []string{
		"https://app.example.test/",
		"https://app.example.test/app/orders/search?limit=1",
	} {
		if rule, ok := s.match(entry(t, raw)); !ok || rule != "https://APP.EXAMPLE.TEST:443" {
			t.Errorf("expected origin match for %s: %q", raw, rule)
		}
	}
	for _, raw := range []string{
		"http://app.example.test/app/orders/search",
		"https://api.example.test/app/orders/search",
		"https://app.example.test.evil.test/app/orders/search",
		"https://app.example.test:8443/app/orders/search",
	} {
		if rule, ok := s.match(entry(t, raw)); ok {
			t.Errorf("unexpected origin match for %s: %q", raw, rule)
		}
	}
	if rule, ok := scopeFor(t, "https://app.example.test/").match(entry(t, "https://app.example.test/app/users")); !ok || rule != "https://app.example.test/" {
		t.Errorf("trailing slash origin rule failed: %q", rule)
	}
}

func TestHostnameWildcardMatchesMultipleOrigins(t *testing.T) {
	s := scopeFor(t, "*example*")
	for _, raw := range []string{
		"https://app.example.test/app/users",
		"https://api.example.test/api/v1/users",
		"https://health.example.test/practicehub/app/users",
	} {
		if _, ok := s.match(entry(t, raw)); !ok {
			t.Errorf("wildcard failed to match %s", raw)
		}
	}
}
