// Package aiagentblocklist is a feed client for the AI Agent Blocklist
// (https://www.aiagentblocklist.com): a daily list of AI agent domains and
// device identifiers (browser extension IDs, macOS bundle IDs, Windows
// package IDs, process names, npm and PyPI packages, IDE plugin IDs).
//
// The client downloads the subscriber files over HTTPS with conditional
// requests, keeps them on disk, and matches hosts, URLs, extensions,
// processes and packages locally. There is no per-request lookup API.
//
//	c, err := aiagentblocklist.New("") // token from AIAGENTBLOCKLIST_TOKEN
//	bl, err := c.LoadBlocklist(ctx)
//	if e := bl.CheckDomain("https://api.example-agent.ai/v1"); e != nil {
//		fmt.Println("listed:", e.ToolName, e.AgentType)
//	}
//
// The package uses the standard library only.
package aiagentblocklist

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Version is the client version.
const Version = "1.0.0"

// DefaultBaseURL is the feed host.
const DefaultBaseURL = "https://www.aiagentblocklist.com"

// DefaultTimeout is the default timeout for one request, body included.
const DefaultTimeout = 30 * time.Second

// TokenEnv is the environment variable read when New gets an empty token.
const TokenEnv = "AIAGENTBLOCKLIST_TOKEN"

// DefaultUserAgent is sent with every request unless WithUserAgent is used.
const DefaultUserAgent = "aiagentblocklist-go/" + Version + " (+https://www.aiagentblocklist.com)"

// Files lists every file in the subscriber download folder. Sync uses it
// when no names are given.
var Files = []string{
	"aab_full.csv",
	"aab_full.json",
	"domains.txt",
	"firewall_edl.txt",
	"hosts.txt",
	"proxy.pac",
	"dns_rpz.zone",
	"chrome_extension_blocklist.json",
	"edge_extension_blocklist.json",
	"chrome_edge_extension_blocklist.reg",
	"chrome_edge_extensions.mobileconfig",
	"firefox_extension_ids.txt",
	"macos_bundle_ids.txt",
	"windows_package_ids.txt",
	"process_names.txt",
	"npm_packages.txt",
	"pypi_packages.txt",
	"counts.json",
	"README.txt",
}

var (
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
	fileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_]*\.(csv|json|txt|pac|zone|reg|mobileconfig)$`)
)

// Client downloads feed files for one subscription token. A Client is safe
// for concurrent use, but two goroutines should not call DownloadTo for the
// same target path at the same time.
type Client struct {
	token     string
	baseURL   string
	userAgent string
	timeout   time.Duration
	hc        *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL replaces the feed host, for example with a local mirror or a
// test server. A trailing slash is ignored.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(strings.TrimSpace(u), "/") }
}

// WithTimeout sets the timeout of the default HTTP client. It has no effect
// when WithHTTPClient is also used; set the timeout on that client instead.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithUserAgent replaces the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// WithHTTPClient uses hc for every request, for example one with a custom
// proxy, TLS settings or transport for tests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.hc = hc }
}

// New returns a Client. When token is empty it is read from the
// AIAGENTBLOCKLIST_TOKEN environment variable. The token must be exactly 32
// letters and digits; otherwise New returns an error matching ErrToken and
// no request is made.
func New(token string, opts ...Option) (*Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv(TokenEnv))
	}
	if token == "" {
		return nil, &Error{Message: "no token given and " + TokenEnv + " is empty", Kind: ErrToken}
	}
	if !tokenRe.MatchString(token) {
		return nil, &Error{Message: "the token must be exactly 32 letters and digits", Kind: ErrToken}
	}
	c := &Client{
		token:     token,
		baseURL:   DefaultBaseURL,
		userAgent: DefaultUserAgent,
		timeout:   DefaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	if c.hc == nil {
		// http.DefaultTransport honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY.
		c.hc = &http.Client{Timeout: c.timeout}
	}
	return c, nil
}

// ValidFileName reports whether name is an acceptable feed file name.
func ValidFileName(name string) bool { return fileNameRe.MatchString(name) }

// FileURL returns the full download URL of one file. It returns an error
// matching ErrFileName for names such as "../x" or "list.exe".
func (c *Client) FileURL(name string) (string, error) {
	if !ValidFileName(name) {
		return "", &Error{Message: "not a feed file name: " + quoteName(name), Kind: ErrFileName}
	}
	return c.baseURL + "/download/" + c.token + "/" + name, nil
}

func quoteName(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return "\"" + s + "\""
}

func (c *Client) newRequest(ctx context.Context, method, name string) (*http.Request, error) {
	u, err := c.FileURL(name)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, &Error{Message: "cannot build the request for " + name, Err: err}
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	return req, nil
}

func (c *Client) do(req *http.Request, name string) (*http.Response, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		// Strip the URL (it holds the token) from the wrapped error.
		if ue, ok := err.(interface{ Unwrap() error }); ok && ue.Unwrap() != nil {
			err = ue.Unwrap()
		}
		return nil, &Error{Message: "request for " + name + " failed", Err: err}
	}
	return resp, nil
}

// Open starts a download and returns the response body as a stream. The
// caller must close it. Use Open to feed a file straight into a parser,
// a hash or a writer without holding it in memory.
func (c *Client) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	req, err := c.newRequest(ctx, http.MethodGet, name)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req, name)
	if err != nil {
		return nil, err
	}
	if err := statusError(resp.StatusCode, name); err != nil {
		drain(resp.Body)
		return nil, err
	}
	return resp.Body, nil
}

// Download returns the full body of one file.
func (c *Client) Download(ctx context.Context, name string) ([]byte, error) {
	body, err := c.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, &Error{Message: "reading " + name + " failed", Err: err}
	}
	return data, nil
}

// DownloadTo fetches one file into path with a conditional GET.
//
// The ETag of the last download is kept in path + ".etag" and sent as
// If-None-Match. On 304, or on a 200 whose ETag has the same bare value as
// the stored one, the file is left as it is and DownloadTo returns false.
// Otherwise the body is written to a temporary file in the same directory
// and renamed over path, and DownloadTo returns true.
func (c *Client) DownloadTo(ctx context.Context, name, path string) (bool, error) {
	req, err := c.newRequest(ctx, http.MethodGet, name)
	if err != nil {
		return false, err
	}
	sidecar := path + ".etag"
	stored := ""
	if fileExists(path) {
		if b, err := os.ReadFile(sidecar); err == nil {
			stored = strings.TrimSpace(string(b))
		}
	}
	if stored != "" {
		req.Header.Set("If-None-Match", stored)
	}
	resp, err := c.do(req, name)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		drain(resp.Body)
		return false, nil
	}
	if err := statusError(resp.StatusCode, name); err != nil {
		drain(resp.Body)
		return false, err
	}
	fresh := strings.TrimSpace(resp.Header.Get("ETag"))
	if stored != "" && fresh != "" && BareETag(stored) == BareETag(fresh) {
		drain(resp.Body)
		return false, nil
	}
	if err := writeAtomic(path, resp.Body); err != nil {
		return false, &Error{Message: "writing " + name + " failed", Err: err}
	}
	if err := os.WriteFile(sidecar, []byte(fresh), 0o644); err != nil {
		return true, &Error{Message: "writing the ETag file for " + name + " failed", Err: err}
	}
	return true, nil
}

// Sync calls DownloadTo for each name into dir and reports which files
// changed. With no names it syncs every file in Files. It stops at the
// first error and returns the results gathered so far.
func (c *Client) Sync(ctx context.Context, dir string, names ...string) (map[string]bool, error) {
	if len(names) == 0 {
		names = Files
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		changed, err := c.DownloadTo(ctx, n, filepath.Join(dir, n))
		if err != nil {
			return out, err
		}
		out[n] = changed
	}
	return out, nil
}

// LoadBlocklist downloads aab_full.json and parses it.
func (c *Client) LoadBlocklist(ctx context.Context) (*Blocklist, error) {
	body, err := c.Open(ctx, "aab_full.json")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return ReadBlocklist(body)
}

// BareETag strips the weak prefix W/, the quotes and a "-gzip" suffix, so
// tags from compressed and uncompressed answers compare equal.
func BareETag(tag string) string {
	t := strings.TrimSpace(tag)
	if len(t) >= 2 && strings.EqualFold(t[:2], "W/") {
		t = t[2:]
	}
	t = strings.Trim(t, "\"")
	t = strings.TrimSuffix(t, "-gzip")
	return t
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func drain(r io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, 64<<10))
}

func writeAtomic(path string, r io.Reader) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, err = io.Copy(tmp, r)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmpName, 0o644)
	}
	if err == nil {
		err = os.Rename(tmpName, path)
	}
	if err != nil {
		// Only the half-written temporary file this call created is removed.
		_ = os.Remove(tmpName)
	}
	return err
}
