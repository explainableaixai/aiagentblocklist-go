# aiagentblocklist-go

A Go module for the [AI Agent Blocklist](https://www.aiagentblocklist.com/) feed. It pulls the daily files to disk with conditional requests, parses the JSON edition from any `io.Reader`, and answers lookups from maps held in memory.

There are no third-party imports. The module fits inside the programs Go teams already operate at the network edge: a sidecar container, a resolver plugin, an egress proxy, a log shipper or an admission webhook.

```bash
go get github.com/explainableaixai/aiagentblocklist-go@v1.0.0
```

Go 1.19 or newer. Package name `aiagentblocklist`; most snippets below import it as `aab`.

## The problem, seen from the infrastructure side

An AI agent does not wait for a person to click. It opens pages, fills in forms, calls APIs and runs shell commands, and it does all of that with the cookies, tokens and file access of whoever installed it. If nobody approved that agent, your network now carries a new actor that holds real credentials and reports to no one.

AI browsers raise the stakes, because the browser is where single sign-on sessions live. A web page can carry hidden instructions that an agent reads as a task; our write-up on [how prompt injection steers AI browsers](https://www.aiagentblocklist.com/ai-browsers/ai-browser-prompt-injection.php) walks through the pattern. MITRE keeps a public catalogue of these adversary techniques in [ATLAS](https://atlas.mitre.org/), which is a useful map for threat modelling.

Go engineers usually meet this from the plumbing end. Someone asks the team that runs the proxy, the internal resolver or the SIEM pipeline to "do something about agents", and the honest answer starts with a current list to check against. This module is that list, plus a quick way to consult it.

## What the feed contains

The list holds 2,600+ AI agent domains and 5,300+ device identifiers, and it is rebuilt every day while the file links stay the same. Identifiers include browser extension IDs for Chrome, Edge and Firefox, macOS bundle IDs, Windows package IDs, process names, npm and PyPI package names, Homebrew casks and formulae, and IDE plugin IDs.

Every row carries an `agent_type` such as AI browser, Coding agent, MCP server, Voice agent or Workflow automation and RPA. It also carries a `kind` that says what the identifier is, and a `risk_grade` from Low to Severe (or "Not graded"). Shadow agents are the usual starting point; our page on [agents nobody signed off on](https://www.aiagentblocklist.com/ai-agents/shadow-ai-agents.php) explains why they are hard to see without a list.

Each subscriber gets a private folder addressed by a 32-character token. Its index page sits at `/download/<TOKEN>/` on the site, with every file one level below it.

These are the files a Go service at the network edge usually wants, ordered from resolver to proxy:

| File | Typical consumer in a Go shop |
|---|---|
| `dns_rpz.zone` | Resolvers that load a response policy zone |
| `domains.txt` | Resolver and proxy plugins that read one domain per line |
| `hosts.txt` | `0.0.0.0` sinkhole lines for hosts files |
| `proxy.pac` | Browser proxy auto-config served from an internal host |
| `firewall_edl.txt` | Perimeter firewalls that poll a host list over HTTPS |
| `aab_full.json` | This module: `LoadBlocklist`, `ReadBlocklist`, `BlocklistFromFile` |
| `counts.json` | A cheap size and freshness probe for dashboards |

The remaining files serve endpoint and browser teams rather than network code. Chrome and Edge get ready policy documents (JSON, a registry import and a macOS profile), and plain text lists cover Firefox add-ons, Mac apps, Windows packages, processes, npm and PyPI. A CSV twin of the JSON and a plain-text README round out the folder.

## Quick start

Put the token in the environment so it stays out of your code and your container image layers.

```bash
export AIAGENTBLOCKLIST_TOKEN=YOUR32CHARACTERDOWNLOADTOKEN0000
```

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	aab "github.com/explainableaixai/aiagentblocklist-go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := aab.New("") // empty: read AIAGENTBLOCKLIST_TOKEN
	if err != nil {
		log.Fatal(err)
	}
	bl, err := client.LoadBlocklist(ctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, probe := range []string{
		"https://api.example-agent.ai/v1/tasks",
		"docs.example.org",
	} {
		if e := bl.CheckDomain(probe); e != nil {
			fmt.Printf("%s -> listed as %s (%s)\n", probe, e.AgentType, e.Ident)
		} else {
			fmt.Printf("%s -> not listed\n", probe)
		}
	}
}
```

`New` checks the token shape before any network traffic, so a typo in a Helm value fails at start-up with a clear message. Lookups after that never touch the network.

## Method table

| Function or method | Returns | Notes |
|---|---|---|
| `New(token, opts...)` | `*Client, error` | Empty token reads `AIAGENTBLOCKLIST_TOKEN`; options `WithBaseURL`, `WithTimeout`, `WithUserAgent`, `WithHTTPClient` |
| `(*Client).FileURL(name)` | `string, error` | Full URL; rejects names outside the feed naming pattern |
| `(*Client).Open(ctx, name)` | `io.ReadCloser, error` | Streams one file; you close it |
| `(*Client).Download(ctx, name)` | `[]byte, error` | Whole body in memory |
| `(*Client).DownloadTo(ctx, name, path)` | `bool, error` | Conditional GET with an `.etag` sidecar; true when the file changed |
| `(*Client).Sync(ctx, dir, names...)` | `map[string]bool, error` | `DownloadTo` for each name; all files when none given |
| `(*Client).LoadBlocklist(ctx)` | `*Blocklist, error` | Streams and parses `aab_full.json` |
| `ReadBlocklist(r)` | `*Blocklist, error` | Parse from any `io.Reader` |
| `BlocklistFromFile(path)`, `BlocklistFromJSON(b)` | `*Blocklist, error` | Offline loading |
| `(*Blocklist).CheckDomain(hostOrURL)` | `*Entry` | Parent domain matching on label boundaries |
| `(*Blocklist).CheckExtension(id)` | `*Entry` | Browser extensions and IDE plugins, any case |
| `(*Blocklist).CheckProcess(name)` | `*Entry` | Process names; `.exe` optional; directories ignored |
| `(*Blocklist).CheckPackage(eco, name)` | `*Entry` | `"npm"` or `"pypi"` |
| `(*Blocklist).Check(id)` | `*Entry` | Domain rules first, then any identifier |
| `(*Blocklist).Filter(agentType, kind, grade)` | `[]Entry` | Empty string means "any" |
| `Domains()`, `AgentTypes()`, `Kinds()` | `[]string` | Copies, safe to modify |
| `NormalizeHost(s)`, `NormalizePyPI(s)`, `BareETag(s)` | `string` | The helpers the matchers use |

A `nil` entry means "not listed". The `Blocklist` fields `Product`, `Version`, `Counts`, `Columns` and `Entries` are exported for reporting.

## Example 1: a sidecar daemon with hot reload

The shape we see most often is a small process next to the real workload. It syncs the files into a shared volume, swaps the parsed list in memory, and exposes a loopback endpoint the main container can query.

The trick is `sync/atomic`. A `*Blocklist` never changes after it is built, so readers can hold an old pointer while the refresher stores a new one, without any lock on the hot path.

```go
var current atomic.Pointer[aab.Blocklist]

func refresh(ctx context.Context, c *aab.Client, dir string) {
	changed, err := c.Sync(ctx, dir, "aab_full.json", "domains.txt", "dns_rpz.zone")
	if err != nil {
		log.Printf("sync: %v (serving the previous copy)", err)
		return
	}
	if !changed["aab_full.json"] && current.Load() != nil {
		return // 304 Not Modified: nothing to parse
	}
	bl, err := aab.BlocklistFromFile(filepath.Join(dir, "aab_full.json"))
	if err != nil {
		log.Printf("parse: %v", err)
		return
	}
	current.Store(bl)
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	bl := current.Load()
	if bl == nil {
		http.Error(w, "warming up", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(bl.Check(r.URL.Query().Get("q")))
}
```

Load the file from disk on start-up before the first sync. A pod that restarts during a network outage then serves the last good copy instead of failing its readiness probe.

The full program, with signal handling and a `/healthz` route, is in [`examples/syncd`](examples/syncd/main.go). A loop of every few hours is plenty, since the list itself changes once a day.

## Example 2: streaming through io.Reader

`Open` hands back the raw response body, and `ReadBlocklist` accepts any reader. That means you can parse, hash and archive in a single pass without buffering the JSON twice.

```go
body, err := client.Open(ctx, "aab_full.json")
if err != nil {
	return err
}
defer body.Close()

archive, err := os.Create("/var/lib/aab/archive/latest.json")
if err != nil {
	return err
}
defer archive.Close()

sum := sha256.New()
tee := io.TeeReader(body, io.MultiWriter(archive, sum))

bl, err := aab.ReadBlocklist(tee)
if err != nil {
	return err
}
log.Printf("version %s, %d rows, sha256 %x", bl.Version, len(bl.Entries), sum.Sum(nil))
```

The same function reads a copy baked into a binary with `embed`, an object pulled from your artifact store, or a gzip stream you keep for audits.

```go
//go:embed snapshot/aab_full.json
var snapshot []byte

func fallbackList() (*aab.Blocklist, error) {
	return aab.ReadBlocklist(bytes.NewReader(snapshot))
}
```

An embedded snapshot is handy for air-gapped builds. Refresh it in your release pipeline so it never drifts far from the live file.

## Example 3: a resolver plugin

If your resolver already loads a response policy zone, you may not need any Go code at all: sync `dns_rpz.zone` and point the resolver at it. The Wikipedia article on the [response policy zone](https://en.wikipedia.org/wiki/Response_policy_zone) mechanism covers the format, and [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) covers the record types underneath.

When you run a custom resolver written in Go, the check fits in the query handler. The sketch below follows the plugin interface used by CoreDNS and the `miekg/dns` types that interface relies on; those imports belong to your plugin, not to this module.

```go
type AgentGuard struct {
	Next  plugin.Handler
	List  *atomic.Pointer[aab.Blocklist]
	Allow map[string]bool // exceptions your security team approved
}

func (g AgentGuard) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	name := strings.TrimSuffix(r.Question[0].Name, ".")
	if bl := g.List.Load(); bl != nil && !g.Allow[name] {
		if e := bl.CheckDomain(name); e != nil {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			w.WriteMsg(m)
			agentHits.WithLabelValues(e.AgentType).Inc()
			return dns.RcodeNameError, nil
		}
	}
	return plugin.NextOrFailure("agentguard", g.Next, ctx, w, r)
}

func (g AgentGuard) Name() string { return "agentguard" }
```

The parent domain rule matters here. A query for `edge.api.example-agent.ai` is answered with NXDOMAIN because `example-agent.ai` is listed, while `notexample-agent.ai` passes through untouched.

For deployment patterns beyond Go code, our guide to [blocking AI agents at the DNS layer](https://www.aiagentblocklist.com/network/dns-block-ai.php) compares resolver options. Remember to exempt names your organisation has approved before you flip the switch.

## Example 4: an egress proxy hook

A forward proxy sees the destination host in two places: in `CONNECT host:443` for TLS, and in the absolute URL for plain HTTP. Both reach the check through `r.Host` or `r.URL.Host`, and `CheckDomain` strips the port for you.

```go
func guard(bl *aab.Blocklist, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if r.Method != http.MethodConnect && r.URL.Host != "" {
			host = r.URL.Host
		}
		if e := bl.CheckDomain(host); e != nil {
			log.Printf("deny %s %s type=%q", r.Method, host, e.AgentType)
			http.Error(w, "blocked by policy: AI agent destination", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

[`examples/blockproxy`](examples/blockproxy/main.go) wraps this in a working proxy with CONNECT tunnelling, so you can try it with `curl -x`. It is a teaching example; production traffic belongs in a hardened proxy that calls the same check.

Firewalls that read external dynamic lists can skip code entirely and fetch `firewall_edl.txt` from a host you control. Our [firewall setup guide for AI agent domains](https://www.aiagentblocklist.com/network/block-ai-agents-firewall.php) shows the general flow.

## Example 5: one-off checks from a shell

[`examples/checkfile`](examples/checkfile/main.go) reads the JSON from a path or standard input and exits with status 1 when anything is listed. That makes it a neat building block for scripts and CI jobs.

```bash
go run ./examples/checkfile -feed /var/lib/aab/aab_full.json \
    https://app.sample-browser.app SampleAgent.exe com.example.agentbrowser

# Chrome policy JSON for one agent type, read from stdin
go run ./examples/checkfile -policy "Browser agent" < /var/lib/aab/aab_full.json
```

The second form calls `Filter("Browser agent", "chrome_ext", "")` and wraps the IDs in an `ExtensionInstallBlocklist` object. Swap the agent type to build narrower policies than the ready-made file.

## Contexts, deadlines and cancellation

Every network method takes a `context.Context` as its first argument. Cancelling it aborts the request, and the error you get back still satisfies `errors.Is(err, context.Canceled)` or `context.DeadlineExceeded`.

The default HTTP client has a 30 second timeout that covers the whole exchange, body included. Change it with `WithTimeout`, or pass your own `*http.Client` with `WithHTTPClient` when you need a custom transport, a corporate proxy or mutual TLS.

Proxy settings come from the usual environment variables (`HTTPS_PROXY`, `NO_PROXY`) through the standard transport. The token itself travels only inside the URL path to the feed host, and the client strips that URL from wrapped network errors so it does not end up in your logs.

## Errors

Every error from this package is an `*aab.Error` with `Status`, `Message`, `Kind` and `Err`. Use `errors.Is` against the sentinels, or `errors.As` when you want the HTTP status.

| Sentinel | When | Suggested reaction |
|---|---|---|
| `ErrToken` | Token missing or not 32 letters and digits | Fix configuration; nothing was sent |
| `ErrFileName` | Name outside the feed naming pattern | Fix the caller |
| `ErrNotFound` | HTTP 404: unknown token or unknown file | Check the token and the file name |
| `ErrAccessEnded` | HTTP 403: subscription ended or paused | Keep serving the last copy and alert a human |
| `ErrHTTP` | Any other non-2xx status | Retry on the next cycle |
| (none) | Network, disk or JSON failure; `Status` is 0 | Inspect `Err`; retry later |

```go
changed, err := client.DownloadTo(ctx, "dns_rpz.zone", "/etc/resolver/aab.zone")
var apiErr *aab.Error
switch {
case errors.Is(err, aab.ErrAccessEnded):
	alert("AI Agent Blocklist access ended; zone frozen at last good copy")
case errors.As(err, &apiErr) && apiErr.Status >= 500:
	log.Printf("feed host returned %d; will retry", apiErr.Status)
case err != nil:
	log.Printf("sync failed: %v", err)
case changed:
	reloadResolver()
}
```

A failed `DownloadTo` never touches the existing file. The new body is written to a temporary file in the same directory and renamed into place, so readers see either the old content or the new content, nothing half-written.

## How the conditional download works

`DownloadTo` stores the response `ETag` in `<path>.etag` and sends it back as `If-None-Match`. A 304 answer returns `false` and leaves both files alone.

Compressed responses can carry a weak tag (`W/"..."`) or a `-gzip` suffix. `BareETag` strips those, and a 200 whose bare tag equals the stored one also counts as "unchanged", so a gzip-aware intermediary cannot trigger needless rewrites and reloads.

The sidecar is only trusted when the data file exists next to it. Move the data file away by hand and the next call does a full download, which is what you want after restoring a volume.

## Matching rules in detail

- **Hosts.** `CheckDomain` accepts a bare host or a full URL. It strips scheme, user info, port, path, query and fragment, lowercases, and drops a trailing dot, then tries the name and each parent on label boundaries.
- **Only domains count for hosts.** A bundle ID such as `com.example.agentbrowser` looks like a host but never matches as one; `Check` finds it through the identifier map instead.
- **Extensions.** One case-insensitive map covers Chrome, Edge and Firefox extensions plus VS Code, Open VSX and JetBrains plugins.
- **Processes.** Paths are cut to the base name, case is ignored, and `.exe` is optional in both directions, so `C:\Tools\SampleAgent.exe`, `sampleagent` and `SAMPLEAGENT.EXE` all hit the same row.
- **Packages.** npm names compare in lowercase. PyPI names use the [PEP 503](https://peps.python.org/pep-0503/) rule, so `Demo_MCP.Server` and `demo-mcp-server` are the same project.
- **Duplicates.** When several rows share an identifier, the first row in the file wins.

All maps are built once when the list loads. A lookup is a few map reads, cheap enough to run on every DNS query or proxy request.

## Production notes

- **Memory.** The full list parses into a few megabytes of structs and maps. Two copies exist briefly during a swap.
- **One writer per path.** `DownloadTo` is safe to call from many goroutines for different paths. Give each replica its own directory, or let one sidecar write and the others read.
- **Start-up order.** Load from disk first, then sync. A cold start without network access still serves yesterday's list.
- **Readiness.** Report not-ready until the first list is loaded, as in the sidecar example.
- **Exceptions.** Keep an allow map for agents your organisation has approved, and check it before the blocklist. The NIST [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) is a good reference when writing down why each exception exists.
- **Metrics.** Count hits by `AgentType` rather than by domain, so dashboards stay readable and you can see which categories people actually reach for.

## FAQ

### Does the module send our lookups anywhere?

No. The only outbound requests are downloads of feed files from the folder your token opens. Every check runs against maps in your own process, so hostnames from your traffic never leave your network.

### How often should a daemon call Sync?

Every few hours is more than enough, because the list is rebuilt once a day. Conditional requests make the extra calls cheap: an unchanged file costs one small 304 answer.

### Can several replicas share one token?

Yes. Each replica downloads on its own schedule and keeps its own ETag sidecars. If you run many replicas, a single sync job writing to a shared read-only volume keeps the request count low.

### What happens when our subscription ends?

Requests return HTTP 403 and the client returns an error matching `ErrAccessEnded`. Files already on disk stay as they are, and the sidecar example keeps serving them, so nothing breaks suddenly; it just stops getting newer.

### Why does a coding agent's npm package not show up in CheckDomain?

`CheckDomain` looks only at rows of kind `domain`. Use `CheckPackage("npm", name)` for packages, `CheckProcess` for running binaries, or `Check` for strings of unknown type, such as a field pulled from an audit log.

### Can we control MCP servers with this?

Partly. Rows with agent type "MCP server" include domains, npm and PyPI packages and command names, so you can block them at the resolver, the package proxy or the endpoint. Our notes on [keeping MCP servers under control](https://www.aiagentblocklist.com/mcp/block-mcp-servers.php) cover the policy side.

### Which Go versions are supported?

Go 1.19 and later. The module needs nothing outside the standard library, which keeps your `go.sum` unchanged and your supply chain review short.

### Where do we get a token?

Choose a plan on the [subscription plans page](https://www.aiagentblocklist.com/pricing.php). Questions about access, invoices or file formats go through the [contact form](https://www.aiagentblocklist.com/contact.php) or to info@alpha-quantum.com.

## Links

- Source and issues: [github.com/explainableaixai/aiagentblocklist-go](https://github.com/explainableaixai/aiagentblocklist-go)
- API documentation: [pkg.go.dev](https://pkg.go.dev/github.com/explainableaixai/aiagentblocklist-go)
- Changes: [CHANGELOG.md](CHANGELOG.md)
- License: [MIT](LICENSE)

Product names are trademarks of their respective owners.

## Related

Looking for a wider net? There is a separate [AI tools blocklist](https://www.aitoolsblocklist.com) for AI apps and sites in general, an [app blocklist for MDM](https://www.appblocklist.com) aimed at mobile fleets, and a full [web filtering database](https://www.webfilteringdatabase.com) for category-based filtering.
