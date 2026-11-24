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
)

func TestExcludeStatusesFromLiveOutputAndReports(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/api/ok":
			w.WriteHeader(http.StatusOK)
		case "/api/auth":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	input := fixture(t, "targets", strings.Join([]string{
		server.URL + "/api/ok",
		server.URL + "/api/auth",
		server.URL + "/api/gone",
	}, "\n"))
	var out bytes.Buffer
	file := filepath.Join(t.TempDir(), "visible.txt")
	args := []string{"scan", "-i", input, "-s", server.URL + "/api/*", "--rate-limit", "0", "-es", "404,401", "-o", file}
	if err := execute(args, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := server.URL + "/api/ok 200\n"
	data, err := os.ReadFile(file)
	if err != nil || out.String() != want || string(data) != want || hits.Load() != 4 {
		t.Fatalf("stdout=%q file=%q hits=%d err=%v", out.String(), data, hits.Load(), err)
	}

	dir := t.TempDir()
	args = []string{"scan", "-i", input, "-s", server.URL + "/api/*", "--rate-limit", "0", "-es", "404", "-es", "401", "-o", dir + string(os.PathSeparator)}
	if err := execute(args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"results.txt", "results.csv", "in-scope.txt"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || strings.Contains(string(data), "/api/gone") || strings.Contains(string(data), "/api/auth") {
			t.Fatalf("filtered URL was saved in %s: %q (%v)", name, data, err)
		}
	}
	data, err = os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []Result
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].Status != 200 {
		t.Fatal(rows, err)
	}
}

func TestExcludeStatusFiltersRunCandidatesAndRejectsInvalidInput(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()
	input := fixture(t, "inventory", server.URL+"/api/v1/users\n"+server.URL+"/api/v1/orders\n"+server.URL+"/api/v1/users/search")
	dir := t.TempDir()
	args := []string{"run", "-i", input, "-s", server.URL + "/api/v1/*", "--rate-limit", "0", "-es", "404", "-o", dir + string(os.PathSeparator)}
	var out bytes.Buffer
	if err := execute(args, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || hits.Load() != 2 {
		t.Fatalf("filtered request was not tested or was printed: hits=%d stdout=%q", hits.Load(), out.String())
	}
	for _, name := range []string{"generated.txt", "results.txt"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(data) != 0 {
			t.Fatalf("filtered result was saved in %s: %q (%v)", name, data, err)
		}
	}
	for _, invalid := range []string{"404,", "0", "600", "abc"} {
		if err := execute([]string{"scan", "-i", input, "-s", server.URL + "/*", "-es", invalid}, io.Discard, io.Discard); err == nil {
			t.Errorf("accepted invalid -es value %q", invalid)
		}
	}
	if hits.Load() != 2 {
		t.Fatal("invalid -es value caused a request")
	}
}
