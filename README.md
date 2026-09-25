# gatekit

A small HTTP JSON service that answers questions about Ory Oathkeeper access rules **with Oathkeeper's own code**, so nothing has to guess. It pins Oathkeeper **v25.4.0** (`github.com/ory/oathkeeper v0.40.10-0.20251107121811-2020997ed914`, the commit tagged `v25.4.0`; Go cannot use the tag directly because the module path has no `/v25` suffix).

- Matching goes through `rule.Rule.IsMatching` / `ExtractRegexGroups`, which use the regexp engine (`ory/ladon` `CompileRegex`, `<` `>` delimiters, `dlclark/regexp2` in RE2 mode, 250 ms timeout) or the glob engine (`gobwas/glob`).
- Rules are decoded with `rule.Rule`'s own JSON unmarshaller, so full rule documents are accepted as they are.
- Templates are rendered with `x.NewTemplate` (text/template, `missingkey=zero`, `print`, `printIndex`, sprig). This is what the `header` and `cookie` mutators, the `remote_json` payload and headers, and the `id_token` claims use. After rendering, gatekit applies the same step the handler would: the payload must be JSON, claims go into `jwt.MapClaims`, and cookies are encoded with `http.Request.AddCookie`.

gatekit makes no outbound connections (`http.DefaultTransport` is replaced by a dialer that refuses every connection). It keeps no state.

Used by jinbe (`/api/admin/sites` preview, match, render, migration parity) and by site-operator (re-validation before rendering Rule CRs). If gatekit is down, preview and apply refuse to run. See `docs/SERVICE_PLUG.md` in the auth workspace.

## API

Every endpoint takes and returns JSON. Unknown fields are refused with `400`. `strategy` is optional: `regexp` (the default, as in Oathkeeper) or `glob`.

### `POST /compile`

```bash
curl -s localhost:8080/compile -d '{"patterns":[
  {"id":"web","url":"<https?>://app.dev.example.com/<(?!api/).*>","methods":["GET"]},
  {"id":"typo","url":"https://app.dev.example.com/<(unclosed>","methods":["GET"]},
  {"id":"glob","url":"https://app.dev.example.com/<**>","methods":["GET"]}]}'
```
```json
{"results":[
  {"id":"web","ok":true},
  {"id":"typo","ok":false,"error":"error parsing regexp: missing closing ) in `^(unclosed$`"},
  {"id":"glob","ok":false,"error":"error parsing regexp: invalid nested repetition operator in `^**$`"}]}
```
`warnings` points out patterns that compile but are probably mistakes: empty `methods` (the rule never matches), `http<(s?)>` (it adds two capture groups), and a trailing `/<.*>` (it does not match the bare path).

### `POST /match`

```bash
curl -s localhost:8080/match -d '{"method":"GET","url":"https://app.dev.example.com/orgs/acme?x=1",
  "rules":[{"id":"org","match":{"url":"<https?>://app.dev.example.com/orgs/<[^/]+>","methods":["GET"]}}]}'
```
```json
{"matched":["org"],"verdict":"one","captureGroups":["https","acme"]}
```
The possible verdicts are:
- `one`: Oathkeeper serves the request.
- `none`: 404.
- `multiple`: 500, "Expected exactly one rule but found multiple rules".
- `error`: a rule failed to compile or hit the regex timeout, and Oathkeeper aborts every request with that method. The failing rules are listed in `errors`.

The query string is never part of the match, and the host is case-sensitive.

### `POST /overlap`

```bash
curl -s localhost:8080/overlap -d '{
  "rules":[
    {"id":"site","match":{"url":"<https?>://h/<.*>","methods":["GET","POST"]}},
    {"id":"api","match":{"url":"https://h/api/<[a-z]+>/<[0-9]+>","methods":["GET","DELETE"]}},
    {"id":"carve","match":{"url":"https://o/api/<(?!health).*>","methods":["GET"]}},
    {"id":"health","match":{"url":"https://o/api/health","methods":["GET"]}}],
  "probes":[{"method":"GET","url":"https://h/api/users/7"}],
  "hosts":["h","o"]}'
```
```json
{"overlaps":[{"a":"site","b":"api","method":"GET","exampleUrl":"https://h/api/users/7"}],
 "checked":244,"probes":122,"method":"probe"}
```
- Each overlapping pair is reported once per shared method, with a concrete URL. Oathkeeper answers 500 for that URL.
- `invalid` lists rules the matcher refuses. They are left out of the overlap check. In production, any one of them breaks the gateway for its methods.
- `checked` counts probe × rule evaluations.
- `probes` counts distinct probe URLs.

### `POST /render`

```bash
curl -s localhost:8080/render -d '{"kind":"header","name":"X-User","template":"{{ print .Subject }}:{{ printIndex .MatchContext.RegexpCaptureGroups 1 }}",
  "sample":{"subject":"u-1","extra":{"identity":{"traits":{"email":"a@b.c"}}},"header":{},
   "matchContext":{"url":"https://h/orgs/acme","method":"GET","header":{"X-Tenant":"acme"},
    "pattern":"<https?>://h/orgs/<[^/]+>"}}}'
```
```json
{"value":"u-1:acme","bytes":8}
```
- `kind` is one of `header`, `cookie`, `payload` or `claims`.
- `sample` becomes the `AuthenticationSession`: `.Subject`, `.Extra`, `.Header` (headers set by earlier handlers), and `.MatchContext` (`URL`, `Method`, `Header`, `RegexpCaptureGroups`).
- When `regexpCaptureGroups` is left out and `pattern` is given, the real matcher extracts the capture groups from the URL.
- Template errors come back in `error` with HTTP 200, using Oathkeeper's own wording.
- For `cookie`, `wire` is the `Cookie` header value Oathkeeper sends upstream.
- `warnings` flags:
  - `<no value>` in the output. `missingkey=zero` does not apply to `map[string]interface{}`.
  - Header values Go refuses to send.
  - Values larger than 8 KiB.
  - Non-deterministic functions (`now`, `uuidv4`, `rand*`).
  - `env`, which reads the environment of the process rendering the template.

### Operations

| | |
|---|---|
| `GET /healthz` | process alive |
| `GET /readyz` | `200` after the start-up self-test has run the real matcher and template engine |
| `:9090/metrics` | Prometheus metrics on a separate listener: `gatekit_http_requests_total{route,code}`, `gatekit_http_request_duration_seconds{route}`, `gatekit_overlap_evaluations_total`, Go and process metrics |
| Logs | one JSON line per request on stdout: `log_type` (`access`/`app`), `request_id` (from a well-formed `X-Request-ID`, otherwise generated and echoed back), route, status, duration. Bodies are never logged |

| Env | Default | |
|---|---|---|
| `GATEKIT_LISTEN` | `:8080` | API |
| `GATEKIT_METRICS_LISTEN` | `:9090` | metrics |
| `GATEKIT_MAX_BODY_BYTES` | `1048576` | larger bodies get `413` |
| `GATEKIT_REQUEST_TIMEOUT` | `10s` | `/overlap` budget. The server's write timeout is this value plus 5 s |

Other limits: at most 2000 rules or patterns and 5000 caller probes per request. Headers are capped at 64 KiB, the read timeout is 10 s, and the read-header timeout is 5 s.

## Limits of overlap detection

Deciding whether two regular expressions intersect exactly is intractable in general, and more so with lookaheads. gatekit therefore **probes**, and says so with `"method":"probe"`. A reported overlap is always real: the real matcher matched the example URL against both rules. **An empty result is evidence, not proof.**

How probes are built:
- For each rule, gatekit walks every `<…>` group through sample values while the other groups stay fixed.
- Samples come from four places:
  - a small generator over the group's regex structure (Go `regexp/syntax`, with lookaheads stripped);
  - literal words taken from **every** rule in the set (path pieces, and words inside groups such as the `health` of `(?!health)`, with `/x`, `x` and `x/` variants);
  - the `hosts` list;
  - a fixed dictionary of edge cases (empty, `/`, `x/`, `/x`, nested paths, dotted names, ids).
- Each sample is kept only if regexp2 accepts it for that group.
- All probes are then run against every rule that could serve the probe's host. A rule with a literal host is only compared with rules on the same host and with rules whose host is a pattern.

Because every rule contributes its own literals, a narrower rule inside a broader one is always caught, and so are a literal next to a catch-all and a pattern host over a literal host. The misses are intersections that no sample reaches. For example, `/<[a-m].*>` and `/<.*z>` intersect only on strings like `az`. The generator yields `a…` and `…z`, but not a string that is both. To close such gaps:
- pass likely real URLs in `probes` (route examples, OpenAPI paths, access-log samples);
- design rules that are disjoint by construction: split by host, then by method, then by literal prefix, then by an enumeration plus a negative-lookahead catch-all. This is what Sites generate.

Other notes:
- Under `glob` no sample filter is applied, and host bucketing is off.
- `/overlap` does not simulate a TLS-terminated request with a mismatched scheme. Include both `http` and `https` probes if the scheme matters; `<https?>` generates both.
- Oathkeeper's `invalidRules` (rules that fail handler validation) still take part in matching. gatekit only checks `match`, so pass every rule you expect Oathkeeper to load.

## Build and run

```bash
go test ./... && go vet ./...
docker build -t gatekit .
docker run --rm -p 8080:8080 -p 9090:9090 gatekit
```
The image is distroless (`static-debian12:nonroot`), runs as UID 65532, and contains a single static binary of about 50 MB.
