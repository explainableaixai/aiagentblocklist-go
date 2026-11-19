# Changelog

All notable changes to `github.com/explainableaixai/aiagentblocklist-go` are listed here.

## 1.0.0

First release.

- `New(token, opts...)` with the token from the argument or `AIAGENTBLOCKLIST_TOKEN`, checked against 32 letters and digits before any request. Options: `WithBaseURL`, `WithTimeout` (default 30 s), `WithUserAgent`, `WithHTTPClient`.
- Feed downloads from `https://www.aiagentblocklist.com/download/<TOKEN>/<file>`: `FileURL`, `Open` (streaming `io.ReadCloser`), `Download`, `DownloadTo` (conditional GET with an `.etag` sidecar and atomic replace) and `Sync`.
- `LoadBlocklist`, `ReadBlocklist(io.Reader)`, `BlocklistFromFile` and `BlocklistFromJSON` parse `aab_full.json` into a read-only `Blocklist` with lookup maps built once.
- Matchers: `CheckDomain` (URL normalisation, parent domain matching), `CheckExtension`, `CheckProcess` (`.exe` optional), `CheckPackage` (npm, PyPI with PEP 503), `Check`, plus `Filter`, `Domains`, `AgentTypes` and `Kinds`.
- Errors are `*Error` values that match `ErrNotFound` (404), `ErrAccessEnded` (403), `ErrHTTP`, `ErrToken` and `ErrFileName` with `errors.Is`.
- Standard library only, Go 1.19+.
- Examples: `examples/syncd` (sidecar daemon), `examples/blockproxy` (forward proxy hook) and `examples/checkfile` (offline checks and a Chrome policy).
