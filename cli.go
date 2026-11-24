package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const usage = `Endpoint Hunter v0.1 — endpoint discovery and scoped HTTP validation
  analyze  -i urls.txt
  scope    -i urls.txt -s scope.txt
  scope    --test URL -s scope.txt
  generate -i urls.txt -s scope.txt [--cross-domain] [-o file]
  scan     -i generated.txt -s scope.txt [-c 5] [-H 'Name: value'] [-es 404,401] [-o report.txt | -o directory/]
  run      -i urls.txt -s scope.txt [-c 5] [-H 'Name: value'] [-es 404,401] [-o report.txt | -o directory/]
For -s, use a scope file or a quoted inline wildcard such as '*catalog*'.
Run and scan send GET requests and print URL status rows; redirects show -> destination.
Use --captures for offline review, or --offline for inventory-only run.
Use -o to also save results.
Use COMMAND -h for options.
`

func execute(args []string, out, log io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprint(out, usage)
		return err
	}
	cmd := args[0]
	switch cmd {
	case "analyze", "scope", "generate", "scan", "run":
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(log)
	var input, scopeFile, manifestFile, captureFile, output, test string
	var cross, verbose, offline, templates bool
	var limit, concurrency int
	var timeout time.Duration
	var rate float64
	var userAgent, headerFile string
	var inlineHeaders headerFlags
	var excludedStatuses statusExclusions
	fs.StringVar(&input, "i", "", "URL inventory file")
	fs.BoolVar(&verbose, "verbose", false, "show individual parse warnings")
	noColor := fs.Bool("no-color", false, "disable terminal status colors")
	if cmd != "analyze" {
		fs.StringVar(&scopeFile, "s", "", "scope file or quoted inline wildcard, full URL, or regex: rule")
	}
	if cmd == "scope" {
		fs.StringVar(&test, "test", "", "check a single URL")
	}
	if cmd == "run" || cmd == "generate" {
		fs.StringVar(&manifestFile, "manifest", "", "file of routes declared by the application owner")
		fs.BoolVar(&cross, "cross-domain", false, "generate or rank routes using other in-scope origins")
		fs.IntVar(&limit, "max-candidates", 1000, "maximum generated candidates")
	}
	if cmd == "generate" {
		fs.BoolVar(&templates, "templates", false, "print abstract templates instead of concrete candidates")
	}
	if cmd == "scan" || cmd == "run" {
		fs.StringVar(&captureFile, "captures", "", "saved response and baseline JSONL file")
		fs.IntVar(&concurrency, "c", 5, "maximum concurrent live GET requests")
		fs.IntVar(&concurrency, "concurrency", 5, "maximum concurrent live GET requests")
		fs.DurationVar(&timeout, "timeout", 10*time.Second, "live request timeout")
		fs.Float64Var(&rate, "rate-limit", 2, "maximum live requests per second; 0 disables pacing")
		fs.StringVar(&userAgent, "user-agent", "EndpointHunter/0.1", "live request User-Agent")
		fs.Var(&inlineHeaders, "H", "request header as 'Name: value'; repeatable and overrides --headers")
		fs.Var(&excludedStatuses, "es", "omit response rows with comma-separated HTTP status codes, such as 404,401")
		fs.Var(&excludedStatuses, "exclude-status", "same as -es; repeatable")
		fs.StringVar(&headerFile, "headers", "", "file containing custom HTTP headers")
		fs.StringVar(&output, "o", "", "also save the report to a file or export its sections to a directory (end with /)")
	}
	if cmd == "run" {
		fs.BoolVar(&offline, "offline", false, "analyze inventory without sending requests")
	}
	if cmd == "generate" {
		fs.StringVar(&output, "o", "", "also save the generated data to this file")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if limit < 0 {
		return fmt.Errorf("max-candidates must be nonnegative")
	}
	if cmd == "generate" && templates && manifestFile != "" {
		return fmt.Errorf("--templates cannot be combined with --manifest")
	}
	if offline && captureFile != "" {
		return fmt.Errorf("choose either --offline or --captures")
	}
	var scope Scope
	var err error
	if cmd != "analyze" {
		if inlineScope(scopeFile) {
			scope, err = readScope(strings.NewReader(scopeFile))
			scopeFile = "" // Only filesystem inputs participate in output collision checks.
		} else {
			scope, err = loadScope(scopeFile)
		}
		if err != nil {
			return err
		}
	}
	if test != "" {
		if input != "" {
			return fmt.Errorf("choose either -i or --test")
		}
		e, err := normalize(test)
		if err != nil {
			return err
		}
		rule, ok := scope.match(e)
		_, err = fmt.Fprintf(out, "%s  matched=%t  %s\n", e.URL, ok, rule)
		return err
	}
	if input == "" {
		return fmt.Errorf("supply -i with a URL list")
	}
	live := (cmd == "scan" || cmd == "run") && captureFile == "" && !offline
	var scanner *liveScanner
	if live {
		headers, err := loadHeaders(headerFile)
		if err != nil {
			return err
		}
		inline, err := inlineHeaders.headers()
		if err != nil {
			return err
		}
		for key, values := range inline {
			headers.Del(key)
			for _, value := range values {
				headers.Add(key, value)
			}
		}
		scanner, err = newLiveScanner(scope, liveOptions{Concurrency: concurrency, Timeout: timeout, Rate: rate, UserAgent: userAgent, Headers: headers})
		if err != nil {
			return err
		}
	}
	inv, err := loadInventory(input)
	if err != nil {
		return err
	}
	summarizeInput(log, "input "+input, inv, verbose)
	if cmd == "analyze" {
		return emitJSON(out, analyze(inv.URLs))
	}
	in, excluded := scope.split(inv.URLs)
	if cmd == "scope" {
		fmt.Fprintf(out, "Total unique URLs: %d\nMatching: %d\nExcluded: %d\n", len(inv.URLs), len(in), len(excluded))
		for _, e := range inv.URLs {
			r, ok := scope.match(e)
			fmt.Fprintf(out, "%s  matched=%t  %s\n", e.URL, ok, r)
		}
		return nil
	}
	inputs := []string{input, scopeFile, manifestFile, captureFile, headerFile}
	r := report{included: in, excluded: excluded}
	targets := in
	if cmd == "run" || (cmd == "generate" && manifestFile == "") {
		r.analysis = analyze(in)
		r.templates = inferTemplates(r.analysis, limit)
		if cmd == "generate" && templates {
			fmt.Fprintf(log, "Inferred route templates: %d\n", len(r.templates))
			err := printAndSave(out, output, inputs, func(w io.Writer) error { return writeTemplates(w, r.templates) })
			if err == nil && output != "" {
				fmt.Fprintln(log, "Saved to", output)
			}
			return err
		}
		if manifestFile == "" && (live || cmd == "generate") {
			r.candidates = generateFromInventory(in, scope, cross, limit)
		}
	}
	if manifestFile != "" {
		manifest, err := loadInventory(manifestFile)
		if err != nil {
			return err
		}
		summarizeInput(log, "manifest "+manifestFile, manifest, verbose)
		if manifest.Counts.Unique == 0 {
			return fmt.Errorf("--manifest %q has no usable route URLs; supply one absolute HTTP(S) route URL per line, or omit --manifest for an inventory run", manifestFile)
		}
		r.candidates = generate(in, manifest.URLs, scope, cross, limit)
	}
	if cmd == "generate" {
		fmt.Fprintf(log, "Generated candidates: %d\n", len(r.candidates))
		err := printAndSave(out, output, inputs, func(w io.Writer) error { return writeGenerated(w, r.candidates) })
		if err == nil && output != "" {
			fmt.Fprintln(log, "Saved to", output)
		}
		return err
	}
	if cmd == "run" {
		if live {
			targets = nil
		}
		for _, c := range r.candidates {
			e, err := normalize(c.URL)
			if err != nil {
				return err
			}
			targets = append(targets, e)
		}
	}
	if live {
		if cmd == "run" {
			fmt.Fprintf(log, "Generated candidates: %d\n", len(r.candidates))
		} else {
			fmt.Fprintf(log, "In-scope targets: %d\n", len(targets))
		}
		if err := preflightOutput(output, r.sections(scope, cmd == "run"), inputs); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		r.results, err = scanner.scan(ctx, targets, func(row Result) error {
			if excludedStatuses.has(row.Status) {
				return nil
			}
			return writeStatusRows(out, []Result{row}, !*noColor && terminalColors(out))
		})
		if err != nil {
			return err
		}
	} else {
		saved, err := readCaptures(captureFile, scope, targets)
		if err != nil {
			return err
		}
		r.results = review(targets, scope, saved)
	}
	if cmd == "run" && !live {
		// Inventory rows precede manifest-only rows in the review target list.
		for i := range in {
			if r.results[i].Status == 0 {
				r.results[i].Classification = "OBSERVED"
				r.results[i].Reason = "imported from URL inventory"
			}
		}
	}
	r.results = excludedStatuses.filter(r.results)
	if len(excludedStatuses) > 0 {
		visible := make(map[string]bool, len(r.results))
		for _, row := range r.results {
			visible[row.URL] = true
		}
		if cmd == "run" {
			kept := make([]Candidate, 0, len(r.candidates))
			for _, candidate := range r.candidates {
				if visible[candidate.URL] {
					kept = append(kept, candidate)
				}
			}
			r.candidates = kept
		} else if cmd == "scan" {
			kept := make([]Endpoint, 0, len(r.included))
			for _, endpoint := range r.included {
				if visible[endpoint.URL] {
					kept = append(kept, endpoint)
				}
			}
			r.included = kept
		}
	}
	displayOrder := append([]Result(nil), r.results...)
	sort.Slice(r.results, func(i, j int) bool {
		a, b := r.results[i], r.results[j]
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		return a.URL < b.URL
	})
	if output != "" {
		info, statErr := os.Stat(output)
		if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
		if strings.HasSuffix(output, string(os.PathSeparator)) || (info != nil && info.IsDir()) {
			if err := exportSections(output, r.sections(scope, cmd == "run"), inputs); err != nil {
				return err
			}
		} else {
			if err := safeOutputs([]string{output}, inputs); err != nil {
				return err
			}
			if err := save(output, func(w io.Writer) error { return writeStatusRows(w, displayOrder, false) }); err != nil {
				return err
			}
		}
		fmt.Fprintln(log, "Saved to", output)
	}
	if live {
		return nil
	}
	return writeStatusRows(out, r.results, !*noColor && terminalColors(out))
}

func preflightOutput(name string, sections []reportSection, inputs []string) error {
	if name == "" {
		return nil
	}
	info, err := os.Stat(name)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.HasSuffix(name, string(os.PathSeparator)) || info != nil && info.IsDir() {
		paths := make([]string, 0, len(sections))
		for _, section := range sections {
			paths = append(paths, filepath.Join(name, section.name))
		}
		return safeOutputs(paths, inputs)
	}
	return safeOutputs([]string{name}, inputs)
}

func summarizeInput(w io.Writer, label string, inv Inventory, verbose bool) {
	c := inv.Counts
	fmt.Fprintf(w, "%s: %d entries, %d unique, %d duplicates, %d static, %d invalid\n", label, c.Lines, c.Unique, c.Duplicates, c.Assets, c.Invalid)
	if verbose {
		for _, warning := range inv.Warnings {
			fmt.Fprintln(w, warning)
		}
	}
}
