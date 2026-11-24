package main

import (
	"bytes"
	"encoding/csv"
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

func TestReviewCapturedRedirect(t *testing.T) {
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer destination.Close()
	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		if r.URL.Path == "/api/book" {
			http.Redirect(w, r, destination.URL+"/outside", 302)
			return
		}
		http.NotFound(w, r)
	}))
	defer source.Close()
	// Record two local fixtures. The program under test receives only files.
	client := source.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	var records bytes.Buffer
	for _, sample := range []struct{ kind, path string }{{"baseline", "/api/absent"}, {"response", "/api/book"}} {
		u := source.URL + sample.path
		resp, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		if err := json.NewEncoder(&records).Encode(Capture{Kind: sample.kind, URL: u, Status: resp.StatusCode, Headers: resp.Header, Body: &body}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	args := []string{"scan", "-i", fixture(t, "urls", source.URL+"/api/book\n"+destination.URL+"/outside"), "-s", fixture(t, "scope", source.URL+"/api/*"), "--captures", fixture(t, "records", records.String()), "-o", dir}
	var stdout bytes.Buffer
	if err := execute(args, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), source.URL+"/api/book 302 -> "+destination.URL+"/outside\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if hits.Load() != 0 || sourceHits.Load() != 2 {
		t.Fatal("unexpected network activity")
	}
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []Result
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].Classification != "REDIRECT" || rows[0].Status != 302 || rows[0].RedirectLocation != destination.URL+"/outside" {
		t.Fatal(rows, err)
	}
	csvData, err := os.ReadFile(filepath.Join(dir, "results.csv"))
	if err != nil {
		t.Fatal(err)
	}
	csvRows, err := csv.NewReader(strings.NewReader(string(csvData))).ReadAll()
	if err != nil || len(csvRows) != 2 || csvRows[0][7] != "redirect_location" || csvRows[1][7] != destination.URL+"/outside" {
		t.Fatal(csvRows, err)
	}
}

func TestSampleWorkflow(t *testing.T) {
	dir := t.TempDir()
	if err := execute([]string{"run", "-i", "examples/endpoints.txt", "-s", "examples/scope.txt", "--manifest", "examples/routes.txt", "--captures", "examples/captures.jsonl", "--cross-domain", "-o", dir}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"analysis.json", "results.txt", "results.csv", "results.json", "in-scope.txt", "excluded.txt", "generated.txt"} {
		s, err := os.Stat(filepath.Join(dir, name))
		if err != nil || s.Size() == 0 {
			t.Fatal(name, err)
		}
	}
	gaps, err := loadInventory(filepath.Join(dir, "generated.txt"))
	if err != nil || len(gaps.URLs) != 5 {
		t.Fatal(gaps.Counts, err)
	}
	f, err := os.Open(filepath.Join(dir, "results.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, row := range records[1:] {
		got[row[4]]++
		if strings.Contains(row[1], "archive.example") {
			t.Fatal(row)
		}
	}
	if len(got) != 6 || got["OBSERVED"] != 6 || got["NOT_FOUND"] != 1 || got["POTENTIAL"] != 1 || got["REDIRECT"] != 1 || got["RESTRICTED"] != 1 || got["UNCONFIRMED"] != 1 {
		t.Fatal(got)
	}
}
func TestOutputCollision(t *testing.T) {
	input := fixture(t, "inventory", "https://app.test/api")
	args := []string{"generate", "-i", input, "-s", fixture(t, "scope", "app.test"), "--manifest", input, "-o", input}
	if err := execute(args, io.Discard, io.Discard); err == nil {
		t.Fatal("overwrote input")
	}
	data, err := os.ReadFile(input)
	if err != nil || string(data) != "https://app.test/api" {
		t.Fatal(string(data), err)
	}
}

func TestInlineScopeInventoryRun(t *testing.T) {
	dir := t.TempDir()
	input := fixture(t, "urls", "https://catalog.example.test/books\nhttps://other.test/?tag=catalog")
	args := []string{"run", "-i", input, "-s", "*catalog*", "--offline", "-o", dir}
	// Repeat to exercise collision checks with existing report files.
	for i := 0; i < 2; i++ {
		if err := execute(args, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []Result
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].Classification != "OBSERVED" || rows[0].MatchedRule != "*catalog*" {
		t.Fatal(rows, err)
	}
	capture := fixture(t, "capture", `{"kind":"response","url":"https://catalog.example.test/books","status":404,"body":"missing"}`)
	capturedArgs := []string{"run", "-i", input, "-s", "*catalog*", "-o", dir, "--captures", capture}
	if err := execute(capturedArgs, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0].Classification != "NOT_FOUND" {
		t.Fatal(rows, err)
	}
}
func TestRejectUnusableManifestBeforeExport(t *testing.T) {
	for _, cmd := range []string{"run", "generate"} {
		output := filepath.Join(t.TempDir(), "new")
		scope := fixture(t, "scope", "catalog")
		err := execute([]string{cmd, "-i", "examples/endpoints.txt", "-s", scope, "--manifest", scope, "-o", output}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "no usable route URLs") {
			t.Fatal(err)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("created output", err)
		}
	}
}

func TestTerminalAndFileReportAreIdentical(t *testing.T) {
	args := []string{"run", "-i", "examples/endpoints.txt", "-s", "examples/scope.txt", "--offline"}
	var terminal, withFile bytes.Buffer
	if err := execute(args, &terminal, io.Discard); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "report.txt")
	if err := execute(append(args, "-o", name), &withFile, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(terminal.Bytes(), data) || !bytes.Equal(withFile.Bytes(), data) {
		t.Fatal("stdout and saved report differ")
	}
	for _, line := range strings.Split(strings.TrimSuffix(terminal.String(), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != "NO_CAPTURE" || !strings.HasPrefix(fields[0], "https://") {
			t.Fatalf("unexpected status row %q", line)
		}
	}
	if bytes.Count(data, []byte("\n")) != 6 {
		t.Fatal("expected six scoped inventory rows")
	}
	dir := filepath.Join(t.TempDir(), "sections")
	if err := execute(append(args, "-o", dir+string(os.PathSeparator)), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 8 {
		t.Fatal(files, err)
	}
}

func TestStatusRowsWithCapturesAndManifest(t *testing.T) {
	input := fixture(t, "input", "https://a.test/books?sort=new")
	manifest := fixture(t, "routes", "https://a.test/books/search")
	captures := fixture(t, "captures", `{"kind":"response","url":"https://a.test/books?sort=new","status":200}
{"kind":"response","url":"https://a.test/books/search","status":403}`)
	var stdout bytes.Buffer
	if err := execute([]string{"run", "-i", input, "-s", "*a.test", "--manifest", manifest, "--captures", captures}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "https://a.test/books/search 403\nhttps://a.test/books?sort=new 200\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	stdout.Reset()
	if err := execute([]string{"run", "-i", input, "-s", "*a.test", "--manifest", manifest, "--captures", captures, "-es", "403"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "https://a.test/books?sort=new 200\n"; got != want {
		t.Fatalf("saved-response filter got %q, want %q", got, want)
	}
}

func TestStatusColors(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{{0, "\x1b[90mNO_CAPTURE"}, {201, "\x1b[32m201"}, {302, "\x1b[36m302"}, {403, "\x1b[33m403"}, {502, "\x1b[31m502"}} {
		var out bytes.Buffer
		if err := writeStatusRows(&out, []Result{{URL: "https://app.test/path", Status: tc.status}}, true); err != nil {
			t.Fatal(err)
		}
		if out.String() != "https://app.test/path "+tc.want+"\x1b[0m\n" {
			t.Errorf("unexpected color %q", out.String())
		}
	}
}
