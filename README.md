# Endpoint Hunter v0.1

Endpoint Hunter learns route patterns from a URL inventory, generates concrete candidate endpoints, and sends scoped GET requests to check their responses. It prints each requested URL with the actual HTTP status as the response arrives, and shows redirect destinations:

```text
https://app.example.test/api/v1/orders/search 200
https://app.example.test/api/v1/orders/history 404
https://app.example.test/api/v1/orders/old 302 -> https://app.example.test/api/v1/orders/new
https://app.example.test/api/v1/orders/status NO_RESPONSE
```

The status is the HTTP response code, not proof that a route exists. Structured reports also contain a conservative classification based on a randomly generated missing path. Every outbound request, including the baseline request, must match an explicit scope rule. Redirect responses are recorded and never followed.

## Install and build

Go 1.22 or newer is required. The project uses only the standard library.

```sh
go install github.com/0xUN7H1NK4BLE/endpoint-hunter@latest
endpoint-hunter --help
```

The executable is installed in your Go binary directory, usually `$(go env GOPATH)/bin`. Add that directory to `PATH` if the command is not found. To build from a local checkout instead:

```sh
go build -o endpoint-hunter .
./endpoint-hunter --help
```

## Quick start

Put one absolute HTTP or HTTPS URL on each line of an inventory file. Create a scope file, or pass a quoted inline wildcard. Then run:

```sh
./endpoint-hunter run -i urls.txt -s scope.txt
./endpoint-hunter run -i urls.txt -s '*app.example.test*' -c 5 --rate-limit 2 --timeout 10s
./endpoint-hunter run -i urls.txt -s scope.txt -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json'
```

The run command generates new paths from observed route combinations, sends GET requests for those candidates, and prints one URL and status per response. Imported URLs are used as evidence and are not requested. Defaults are 1000 maximum candidates, five concurrent requests, two requests per second globally, and ten seconds per request. If generation finds more than 1000, the CLI prints the full count and the number retained. Use `--max-candidates 0` to scan all generated candidates.

To inspect candidates without requests:

```sh
./endpoint-hunter generate -i urls.txt -s scope.txt
./endpoint-hunter generate -i urls.txt -s scope.txt -o generated.txt
```

The list is printed to stdout. It is saved only when `-o` is supplied. Each URL has a preceding JSON comment with its source URLs, reason, method, and score. Comments are ignored when the file is used as scanner input. `generate` keeps every candidate by default. Set `--max-candidates N` to keep only the highest-ranked N candidates.

```sh
./endpoint-hunter scan -i generated.txt -s scope.txt -c 5 -o output/
./endpoint-hunter scan -i generated.txt -s scope.txt -es 404,401 -o visible.txt
```

Use `-o results.txt` to save plain status rows or `-o output/` to save a full report directory. A trailing slash selects a directory. Colors appear on interactive terminals; `--no-color` disables them.

## Commands

| Command | Purpose |
| --- | --- |
| `analyze -i urls.txt` | Print per-origin analysis JSON without requests. |
| `scope -i urls.txt -s scope.txt` | Show which inventory URLs match each scope rule. |
| `scope --test URL -s scope.txt` | Test one URL against scope. |
| `generate -i urls.txt -s scope.txt` | Print concrete, deduplicated candidates without requests. |
| `generate -i urls.txt -s scope.txt --templates` | Print abstract inferred route structures. |
| `scan -i generated.txt -s scope.txt` | Request each in-scope URL in the file and print actual statuses. |
| `run -i urls.txt -s scope.txt` | Generate candidates, request them, and print actual statuses. |

`run --offline` retains inventory-only analysis without network requests. `run --captures captures.jsonl` and `scan --captures captures.jsonl` review saved responses without network requests. `--manifest routes.txt` compares concrete routes against the inventory and uses those gaps as candidates. A manifest is optional for normal generation.

Live options for run and scan:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-c`, `--concurrency` | `5` | Maximum concurrent GET requests, from 1 to 100. |
| `--timeout` | `10s` | Per-request timeout. |
| `--rate-limit` | `2` | Maximum requests per second across baseline and candidates; `0` disables pacing. |
| `--user-agent` | `EndpointHunter/0.1` | Request User-Agent. |
| `-H` | none | Add a request header as `Name: value`; repeat for multiple headers. |
| `--headers` | none | File of `Header-Name: value` lines, including optional authentication headers. |
| `-es`, `--exclude-status` | none | Omit responses with comma-separated status codes, for example `-es 404,401`. Repeatable. |
| `--no-color` | off | Disable colored status codes. |

Run and generate also accept `--max-candidates N` and `--cross-domain`. The default limit is 1000 for `run` and unlimited for `generate`; `0` means unlimited in either command. Cross-domain mode proposes paths observed on one in-scope origin for other origins already present in the authorized inventory. The score is a priority aid, not a probability that an endpoint exists.

Headers from `-H` are sent on both baseline and candidate requests. A repeated `-H` for the same name uses the last value. An inline `-H` overrides the same header in `--headers`; `-H 'User-Agent: ...'` also overrides the default user agent. Set the target host through the URL rather than a `Host` header.

The `-es` filter is applied after each request. Matching responses are still tested, but their URL and status are omitted from terminal output and saved status results. With directory output, filtered run candidates are omitted from `generated.txt`, and filtered scan targets are omitted from `in-scope.txt`. Codes must be between 100 and 599.

## Input and scope

The parser reads files line by line. It ignores blank and comment lines, normalizes hostnames and paths, removes duplicate normalized URLs, preserves meaningful trailing slashes, and excludes common static assets. Malformed lines are skipped and counted; `--verbose` shows a few line numbers. Fragments are omitted from requests. Numeric IDs, hyphenated UUIDs, and 24-character hexadecimal IDs are identified for analysis. Generation also treats long mixed-case alphanumeric tokens as likely IDs. Retained unique URLs, candidates, and report rows still use memory.

Scope is mandatory for every command that can produce or request candidates. A missing or empty scope file fails. Rules may be in a TXT file, one per line, or passed inline as a wildcard, full URL, or `regex:` rule. Quote inline wildcards so the shell does not expand them.

```text
# Hostname wildcard
*app.example.test*

# One HTTPS origin, all paths
https://app.example.test

# Full URL wildcards
https://app.example.test/api/*
https://*.example.test/api/v?/*

# Full URL regex using Go regexp syntax
regex:^https://(app|stage)\.example\.test/api/v[0-9]+/.*$
```

Hostname rules match the lowercased hostname. A full URL rule containing only a scheme and host (with or without a trailing slash) matches every path on that exact origin, including its scheme and port. Other full URL rules match the normalized URL, including its query string. `*` matches zero or more characters and `?` matches one. A malformed regex fails closed. The first matching rule is reported. An inventory hostname is never automatically authorized. Use a full URL rule to constrain scheme, port, and path.

## Generation and validation

Generation groups paths by origin and fills missing combinations supported by observed structures. It combines sibling resources with every observed safe suffix, including multi-segment suffixes. Given `/api/v1/users`, `/api/v1/orders`, and `/api/v1/users/settings/privacy`, it proposes `/api/v1/orders/settings/privacy`. For parameterized routes, it treats `/resource/{id}/suffix` as one route template: different IDs with the same suffix do not produce repeated candidates. If a sibling resource shows a suffix absent from the target resource, it proposes one URL using an ID already observed on that target resource. It also completes three-corner route matrices such as `order-history`, `order-status`, and `product-history` → `product-status`. Hyphenated segments are compared part by part; support counts use grouped frequencies instead of comparing every pair of input URLs. Candidate URLs carry their source evidence and a priority score. There is no hidden 64-resource cutoff. Paths observed only with query strings contribute route structure; query values are not copied. The generator uses inventory vocabulary rather than a generic wordlist. It excludes apparent identifiers, obvious state-changing suffixes, suspicious path syntax, common static files, observed routes, and any destination outside scope. This is exhaustive within those observed safe route families, not every arbitrary string permutation. A suggestion can still be irrelevant; inspect its evidence before drawing a conclusion.

The scanner requests a random missing path under an in-scope candidate directory for each origin, when scope permits one. It then requests each candidate once. Responses are read up to 256 KiB. It compares status, content type, redirect location, authentication challenge, allowed methods, body length, digest, and a bounded text similarity sketch. A 200 page that matches the missing-route baseline can be classified `NOT_FOUND`.

| Classification | Meaning |
| --- | --- |
| `POTENTIAL` | Response differs meaningfully from a usable baseline. |
| `RESTRICTED` | A 401 or 403 response differs from the baseline. |
| `REDIRECT` | Redirect destination differs from the baseline; it was not followed. |
| `NOT_FOUND` | Explicit 404/410 or a response matching the baseline. |
| `UNCONFIRMED` | Missing or ambiguous evidence, timeout, connection failure, or shared access gate. |
| `OBSERVED` | Imported inventory URL in offline review. |

One baseline per origin may not represent every application section. The scanner does not retry requests. On a 429 response, it honors a valid `Retry-After` value before later requests. Ctrl-C cancels pending requests. A request that fails before receiving a response prints `NO_RESPONSE`. Redirect destinations are resolved to absolute URLs for display and are never requested automatically.

## Reports

Without `-o`, output stays on the terminal. With `-o output/`, a full run writes:

| File | Contents |
| --- | --- |
| `generated.txt` | Concrete candidates with JSON evidence comments. |
| `inferred-patterns.txt` | Abstract structures inferred from input. |
| `in-scope.txt`, `excluded.txt` | Inventory URLs and scope decisions. |
| `results.txt` | Status, classification, and reason for tested candidates. |
| `results.csv`, `results.json` | Structured results grouped by hostname and URL, including any redirect destination. |
| `analysis.json` | Per-origin analysis. |

Scan writes the scope lists and three result files. A plain `-o report.txt` saves the same status rows shown on the terminal. Output options cannot overwrite existing input files. Reports may contain sensitive URL query values and response details.

## Sample and tests

The `examples/` directory contains synthetic inventory, scope, manifest, and saved response files. Run the sample offline:

```sh
./endpoint-hunter run -i examples/endpoints.txt -s examples/scope.txt \
  --manifest examples/routes.txt --captures examples/captures.jsonl -o output/

gofmt -l *.go
go test ./...
go test -race ./...
go vet ./...
```

Integration tests use local `httptest` servers to verify actual GET requests, timeouts, custom 200 missing pages, scope filtering, and redirect blocking. No test sends requests to external targets.

## Architecture and limits

`parser.go` handles URL input and normalization. `scope.go` enforces allow rules. `analyzer.go` records per-origin structures. `generator.go` handles manifest gaps; `combinations.go` generates evidence-backed combinations from the inventory. `live.go` performs bounded concurrent GET requests. `scanner.go` reviews saved captures. `fingerprint.go` classifies responses. `reporter.go` writes terminal and file output. `cli.go` connects commands and flags.

This version uses GET only, cannot infer route parameters absent from the inventory, and does not authenticate by itself. Use `-H` or `--headers` for an existing authorized session or token. It does not follow redirects, execute JavaScript, or verify application behavior beyond the HTTP response. Broad scope wildcards can include unrelated hosts; prefer host and path rules that express the intended authorization.
