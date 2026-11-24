package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

func emitJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Stage each file in the destination directory so a failed write cannot
// leave a partially written replacement.
func save(name string, write func(io.Writer) error) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".endpoint-hunter-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	buf := bufio.NewWriter(f)
	err = write(buf)
	if err == nil {
		err = buf.Flush()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), name)
}

func safeOutputs(outputs, inputs []string) error {
	for _, name := range outputs {
		info, err := os.Stat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output is not a regular file: %s", name)
		}
		for _, src := range inputs {
			if src == "" {
				continue
			}
			source, err := os.Stat(src)
			if err != nil {
				return err
			}
			if os.SameFile(info, source) {
				return fmt.Errorf("output would overwrite input %s", src)
			}
		}
	}
	return nil
}

func writeGenerated(w io.Writer, items []Candidate) error {
	for _, c := range items {
		data, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(w, "# %s\n%s\n", data, c.URL); err != nil {
			return err
		}
	}
	return nil
}
func writeURLs(w io.Writer, urls []Endpoint, s Scope) error {
	for _, e := range urls {
		rule, _ := s.match(e)
		if _, err := fmt.Fprintf(w, "# %s\n%s\n", rule, e.URL); err != nil {
			return err
		}
	}
	return nil
}
func writeResults(w io.Writer, results []Result, asCSV bool) error {
	csvw := csv.NewWriter(w)
	if asCSV {
		if err := csvw.Write([]string{"hostname", "url", "status", "status_class", "classification", "reason", "scope_rule", "redirect_location"}); err != nil {
			return err
		}
	}
	for _, r := range results {
		status := ""
		if r.Status > 0 {
			status = strconv.Itoa(r.Status)
		}
		if asCSV {
			if err := csvw.Write([]string{r.Hostname, r.URL, status, r.StatusClass, r.Classification, r.Reason, r.MatchedRule, r.RedirectLocation}); err != nil {
				return err
			}
		} else {
			location := ""
			if r.Status >= 300 && r.Status < 400 && r.RedirectLocation != "" {
				location = " -> " + r.RedirectLocation
			}
			if _, err := fmt.Fprintf(w, "[%s] %s  %s%s %s  %s\n", r.Classification, r.URL, status, location, r.StatusClass, r.Reason); err != nil {
				return err
			}
		}
	}
	if asCSV {
		csvw.Flush()
		return csvw.Error()
	}
	return nil
}

type report struct {
	analysis           Analysis
	templates          []TemplateSuggestion
	included, excluded []Endpoint
	candidates         []Candidate
	results            []Result
}

type reportSection struct {
	name  string
	write func(io.Writer) error
}

func (r report) sections(scope Scope, full bool) []reportSection {
	var sections []reportSection
	if full {
		sections = append(sections,
			reportSection{"inferred-patterns.txt", func(w io.Writer) error { return writeTemplates(w, r.templates) }},
			reportSection{"generated.txt", func(w io.Writer) error { return writeGenerated(w, r.candidates) }},
		)
	}
	sections = append(sections,
		reportSection{"in-scope.txt", func(w io.Writer) error { return writeURLs(w, r.included, scope) }},
		reportSection{"excluded.txt", func(w io.Writer) error { return writeURLs(w, r.excluded, scope) }},
		reportSection{"results.txt", func(w io.Writer) error { return writeResults(w, r.results, false) }},
		reportSection{"results.csv", func(w io.Writer) error { return writeResults(w, r.results, true) }},
		reportSection{"results.json", func(w io.Writer) error { return emitJSON(w, r.results) }},
	)
	if full {
		sections = append(sections, reportSection{"analysis.json", func(w io.Writer) error { return emitJSON(w, r.analysis) }})
	}
	return sections
}

// Print in every mode. A named file receives the same bytes as stdout.
func printAndSave(out io.Writer, name string, inputs []string, write func(io.Writer) error) error {
	if name == "" {
		return write(out)
	}
	if err := safeOutputs([]string{name}, inputs); err != nil {
		return err
	}
	return save(name, func(file io.Writer) error { return write(io.MultiWriter(out, file)) })
}

func exportSections(dir string, sections []reportSection, inputs []string) error {
	paths := make([]string, 0, len(sections))
	for _, section := range sections {
		paths = append(paths, filepath.Join(dir, section.name))
	}
	if err := safeOutputs(paths, inputs); err != nil {
		return err
	}
	for i, section := range sections {
		if err := save(paths[i], section.write); err != nil {
			return fmt.Errorf("%s: %w", section.name, err)
		}
	}
	return nil
}

func terminalColors(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func writeStatusRows(out io.Writer, rows []Result, color bool) error {
	// ANSI SGR colors by HTTP status class: unknown, 1xx, 2xx, 3xx, 4xx, 5xx.
	colors := [6]string{"90", "36", "32", "36", "33", "31"}
	w := bufio.NewWriter(out)
	for _, r := range rows {
		label := "NO_CAPTURE"
		if r.StatusClass == "NO_RESPONSE" {
			label = "NO_RESPONSE"
		}
		if r.Status != 0 {
			label = strconv.Itoa(r.Status)
		}
		if color {
			index := r.Status / 100
			if index < 0 || index >= len(colors) {
				index = 0
			}
			label = "\x1b[" + colors[index] + "m" + label + "\x1b[0m"
		}
		if r.Status >= 300 && r.Status < 400 && r.RedirectLocation != "" {
			if _, err := fmt.Fprintln(w, r.URL, label, "->", r.RedirectLocation); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintln(w, r.URL, label); err != nil {
			return err
		}
	}
	return w.Flush()
}
