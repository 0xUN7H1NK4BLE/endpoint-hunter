package main

import (
	"net/http"
	"testing"
)

func TestFingerprint(t *testing.T) {
	baseline := entry(t, "https://app.test/api/missing")
	target := entry(t, "https://app.test/api/books")
	fp := func(e Endpoint, status int, body, location string) fingerprint {
		return makeFingerprint(Capture{URL: e.URL, Status: status, Body: &body, Headers: http.Header{"Location": []string{location}}}, e)
	}
	for _, tc := range []struct {
		name string
		b, f fingerprint
		want string
	}{
		{"soft 404", fp(baseline, 200, "Missing /api/missing", ""), fp(target, 200, "Missing /api/books", ""), "NOT_FOUND"},
		{"generic redirect", fp(baseline, 302, "", "/login?next=%2Fapi%2Fmissing"), fp(target, 302, "", "/login?next=%2Fapi%2Fbooks"), "UNCONFIRMED"},
		{"new redirect", fp(baseline, 404, "no", ""), fp(target, 302, "", "/library"), "REDIRECT"},
		{"auth", fp(baseline, 404, "no", ""), fp(target, 401, "login", ""), "RESTRICTED"},
		{"common gate", fp(baseline, 403, "login", ""), fp(target, 403, "login", ""), "UNCONFIRMED"},
		{"absence", fp(baseline, 200, "no", ""), fp(target, 404, "missing", ""), "NOT_FOUND"},
		{"different", fp(baseline, 404, "no", ""), fp(target, 200, "okay", ""), "POTENTIAL"},
		{"overloaded", fp(baseline, 404, "no", ""), fp(target, 429, "slow", ""), "UNCONFIRMED"},
		{"bad baseline", fp(baseline, 503, "oops", ""), fp(target, 200, "ok", ""), "UNCONFIRMED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classify(tc.f, &tc.b)
			if got != tc.want {
				t.Fatal(got)
			}
		})
	}
	b := fp(baseline, 404, "missing", "")
	f := fp(target, 200, "data", "")
	f.complete = false
	if got, _ := classify(f, &b); got != "UNCONFIRMED" {
		t.Fatal(got)
	}
	if got, _ := classify(f, nil); got != "UNCONFIRMED" {
		t.Fatal(got)
	}
}
func TestStatusClasses(t *testing.T) {
	for n, want := range map[int]string{204: "SUCCESS", 300: "OTHER", 301: "REDIRECT", 308: "REDIRECT", 400: "POTENTIAL", 401: "AUTH_REQUIRED", 403: "FORBIDDEN", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 409: "POTENTIAL", 422: "POTENTIAL", 429: "RATE_LIMITED", 500: "SERVER_ERROR", 599: "SERVER_ERROR", 418: "OTHER"} {
		if got := statusClass(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}
