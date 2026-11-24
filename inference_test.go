package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferenceUsesSameOriginEvidence(t *testing.T) {
	var urls []Endpoint
	for _, path := range []string{"books/42", "books/7", "books/7?q=third", "books/search", "authors/books"} {
		urls = append(urls, entry(t, "https://catalog.test/api/v1/"+path))
	}
	urls = append(urls, entry(t, "https://preview.test/api/v1/books/42"))
	a := analyze(urls)
	got := inferTemplates(a, 1000)
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	for _, s := range got {
		if s.Origin != "https://catalog.test" {
			t.Fatalf("cross-origin inference: %+v", s)
		}
		if s.Template == "/{resource}/{id}/{action}" && (s.ParentCount != 2 || s.AnalogyCount != 1) {
			t.Fatalf("wrong evidence: %+v", s)
		}
	}
	urls = append(urls, entry(t, "https://catalog.test/api/v1/books/42/search"))
	for _, s := range inferTemplates(analyze(urls), 1000) {
		if s.Template == "/{resource}/{id}/{action}" {
			t.Fatalf("suggested observed structure: %+v", s)
		}
	}
	if len(inferTemplates(a, 0)) != len(got) || len(inferTemplates(a, 1)) != 1 {
		t.Fatal("candidate cap ignored")
	}
}
func TestInventoryGeneratesTemplateReport(t *testing.T) {
	input := fixture(t, "urls", "https://catalog.test/api/v1/books/42\nhttps://catalog.test/api/v1/books/search\nhttps://other.test/api/v1/books/7")
	dir := t.TempDir()
	for _, cmd := range []string{"run", "generate"} {
		dest := dir
		name := "inferred-patterns.txt"
		if cmd == "generate" {
			dest = filepath.Join(dir, "templates.txt")
			name = "templates.txt"
		}
		var stdout bytes.Buffer
		args := []string{cmd, "-i", input, "-s", "*catalog*", "-o", dest}
		if cmd == "run" {
			args = append(args, "--offline")
		} else {
			args = append(args, "--templates")
		}
		err := execute(args, &stdout, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "/{resource}/{id}/{action}") || strings.Contains(string(data), "other.test") || strings.Contains(string(data), "books") {
			t.Fatal(string(data))
		}
	}
}
