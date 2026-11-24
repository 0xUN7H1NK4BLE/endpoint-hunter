package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInventoryCandidatesAreConcreteAndScoped(t *testing.T) {
	base := "https://app.test/api/v1/"
	observed := []Endpoint{
		entry(t, base+"users"), entry(t, base+"orders"), entry(t, base+"users/search"),
		entry(t, base+"users/123"), entry(t, base+"users/delete"),
		entry(t, "https://other.test/api/v1/users/profile"),
	}
	s := scopeFor(t, "https://app.test/api/v1/*")
	got := generateFromInventory(observed, s, false, 100)
	if len(got) != 1 || got[0].URL != base+"orders/search" || len(got[0].Evidence) != 2 || got[0].Method != "GET" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
	if len(generateFromInventory(observed, s, false, 0)) != 0 {
		t.Fatal("candidate cap ignored")
	}
}

func TestRunSendsGETAndPrintsActualStatus(t *testing.T) {
	var baselineHits, candidateHits, observedHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "EndpointHunter/0.1" {
			t.Errorf("unexpected request: %s, %s", r.Method, r.Header.Get("User-Agent"))
		}
		switch {
		case strings.Contains(r.URL.Path, ".endpoint-hunter-"):
			baselineHits.Add(1)
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "not found "+r.URL.Path)
		case r.URL.Path == "/api/v1/orders/search":
			candidateHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"results":[]}`)
		default:
			observedHits.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	input := fixture(t, "inventory", server.URL+"/api/v1/users\n"+server.URL+"/api/v1/orders\n"+server.URL+"/api/v1/users/search")
	dir := t.TempDir()
	var out bytes.Buffer
	if err := execute([]string{"run", "-i", input, "-s", server.URL + "/api/v1/*", "--rate-limit", "0", "-o", dir + string(os.PathSeparator)}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), server.URL+"/api/v1/orders/search 200\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if baselineHits.Load() != 1 || candidateHits.Load() != 1 || observedHits.Load() != 0 {
		t.Fatalf("request counts: baseline=%d candidate=%d observed=%d", baselineHits.Load(), candidateHits.Load(), observedHits.Load())
	}
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []Result
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].Classification != "POTENTIAL" || rows[0].Status != 200 {
		t.Fatal(rows, err)
	}
}

func TestLiveScanNeverFollowsRedirectOutOfScope(t *testing.T) {
	var outsideHits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1) }))
	defer outside.Close()
	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		if r.URL.Path == "/api/v1/orders/search" {
			http.Redirect(w, r, outside.URL+"/outside", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer source.Close()
	input := fixture(t, "generated", source.URL+"/api/v1/orders/search\n"+outside.URL+"/outside")
	var out bytes.Buffer
	if err := execute([]string{"scan", "-i", input, "-s", source.URL + "/api/v1/*", "--rate-limit", "0"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), source.URL+"/api/v1/orders/search 302 -> "+outside.URL+"/outside\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if outsideHits.Load() != 0 || sourceHits.Load() != 2 {
		t.Fatalf("unexpected requests: outside=%d source=%d", outsideHits.Load(), sourceHits.Load())
	}
}

func TestLiveScanShowsResolvedRelativeRedirect(t *testing.T) {
	var loginHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/old" {
			http.Redirect(w, r, "/login?next=%2Fapi%2Fold", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/login" {
			loginHits.Add(1)
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	input := fixture(t, "generated", server.URL+"/api/old")
	var out bytes.Buffer
	if err := execute([]string{"scan", "-i", input, "-s", server.URL + "/*", "--rate-limit", "0"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := server.URL + "/api/old 307 -> " + server.URL + "/login?next=%2Fapi%2Fold\n"
	if out.String() != want || loginHits.Load() != 0 {
		t.Fatalf("output=%q login hits=%d", out.String(), loginHits.Load())
	}
}

func TestLiveScanTimeoutDisplaysNoResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}))
	defer server.Close()
	input := fixture(t, "generated", server.URL+"/api/v1/orders/search")
	var out bytes.Buffer
	if err := execute([]string{"scan", "-i", input, "-s", server.URL + "/api/v1/*", "--rate-limit", "0", "--timeout", "10ms"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), server.URL+"/api/v1/orders/search NO_RESPONSE\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLiveScanRecognizesCustom200MissingPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "Missing route: "+r.URL.Path)
	}))
	defer server.Close()
	input := fixture(t, "generated", server.URL+"/api/v1/orders/search")
	dir := t.TempDir()
	if err := execute([]string{"scan", "-i", input, "-s", server.URL + "/api/v1/*", "--rate-limit", "0", "-o", dir + string(os.PathSeparator)}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []Result
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].Classification != "NOT_FOUND" || rows[0].Status != 200 {
		t.Fatal(rows, err)
	}
}

func TestInlineRequestHeadersApplyToBaselineAndCandidate(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer inline-token" || r.Header.Get("X-Trace") != "case-1" || r.Header.Get("User-Agent") != "CustomAgent/1" {
			t.Errorf("request headers were not applied: %v", r.Header)
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	input := fixture(t, "generated", server.URL+"/api/v1/orders/search")
	headerFile := fixture(t, "headers", "Authorization: Bearer file-token\nX-Trace: file-value")
	var out bytes.Buffer
	args := []string{
		"scan", "-i", input, "-s", server.URL + "/api/v1/*", "--rate-limit", "0",
		"--headers", headerFile,
		"-H", "Authorization: Bearer inline-token",
		"-H", "X-Trace: case-1",
		"-H", "User-Agent: CustomAgent/1",
	}
	if err := execute(args, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || out.String() != server.URL+"/api/v1/orders/search 404\n" {
		t.Fatalf("hits=%d output=%q", hits.Load(), out.String())
	}
	for _, bad := range []string{"missing-colon", "Host: outside.test", "X-Bad: line\nbreak"} {
		if err := execute([]string{"scan", "-i", input, "-s", server.URL + "/api/v1/*", "-H", bad}, io.Discard, io.Discard); err == nil {
			t.Errorf("accepted malformed header %q", bad)
		}
	}
	if hits.Load() != 2 {
		t.Fatal("invalid header caused an outbound request")
	}
}
