package aiagentblocklist

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "abcDEF0123456789abcDEF0123456789"

// tempDir makes a directory that is deliberately not removed afterwards.
func tempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "aiagentblocklist-go-test-")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNewTokenValidation(t *testing.T) {
	t.Setenv(TokenEnv, "")
	for _, bad := range []string{"", "short", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("a", 31) + "-", strings.Repeat("ä", 32)} {
		_, err := New(bad)
		if !errors.Is(err, ErrToken) {
			t.Errorf("New(%q) error = %v, want ErrToken", bad, err)
		}
		var e *Error
		if !errors.As(err, &e) || e.Status != 0 {
			t.Errorf("New(%q) should return *Error with status 0", bad)
		}
	}
	if _, err := New(testToken); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestNewTokenFromEnv(t *testing.T) {
	t.Setenv(TokenEnv, " "+testToken+" ")
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.FileURL("domains.txt")
	if u != DefaultBaseURL+"/download/"+testToken+"/domains.txt" {
		t.Fatalf("FileURL = %s", u)
	}
	t.Setenv(TokenEnv, "not-a-token")
	if _, err := New(""); !errors.Is(err, ErrToken) {
		t.Fatalf("bad env token accepted: %v", err)
	}
}

func TestFileURLValidation(t *testing.T) {
	c, _ := New(testToken, WithBaseURL("https://mirror.example.test/"))
	for _, good := range Files {
		u, err := c.FileURL(good)
		if err != nil || u != "https://mirror.example.test/download/"+testToken+"/"+good {
			t.Errorf("FileURL(%q) = %q, %v", good, u, err)
		}
	}
	for _, bad := range []string{"", "../etc/passwd", "aab_full.exe", "_x.txt", "a/b.txt", "domains.txt?x=1", "domains", ".hidden.txt", "dom ains.txt", "x.TXT"} {
		if _, err := c.FileURL(bad); !errors.Is(err, ErrFileName) {
			t.Errorf("FileURL(%q) error = %v, want ErrFileName", bad, err)
		}
	}
}

// feedServer serves the fixture and a scripted sequence for domains.txt.
type feedServer struct {
	mu        sync.Mutex
	srv       *httptest.Server
	agents    []string
	inm       []string
	domainsV  string
	domainsET string
}

func newFeedServer(t *testing.T) *feedServer {
	t.Helper()
	fixtureJSON, err := os.ReadFile("testdata/aab_full.json")
	if err != nil {
		t.Fatal(err)
	}
	fs := &feedServer{domainsV: "example-agent.ai\n", domainsET: `W/"v1-gzip"`}
	prefix := "/download/" + testToken + "/"
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.agents = append(fs.agents, r.Header.Get("User-Agent"))
		fs.inm = append(fs.inm, r.Header.Get("If-None-Match"))
		switch {
		case r.URL.Path == "/download/"+strings.Repeat("P", 32)+"/domains.txt":
			http.Error(w, "paused", http.StatusForbidden)
		case r.URL.Path == "/download/"+strings.Repeat("E", 32)+"/domains.txt":
			http.Error(w, "oops", http.StatusInternalServerError)
		case !strings.HasPrefix(r.URL.Path, prefix):
			http.NotFound(w, r)
		case r.URL.Path == prefix+"aab_full.json":
			w.Header().Set("ETag", `"fx1"`)
			_, _ = w.Write(fixtureJSON)
		case r.URL.Path == prefix+"domains.txt":
			if inm := r.Header.Get("If-None-Match"); inm != "" && BareETag(inm) == BareETag(fs.domainsET) && r.Header.Get("X-Force-200") == "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", fs.domainsET)
			_, _ = io.WriteString(w, fs.domainsV)
		case r.URL.Path == prefix+"hosts.txt":
			// Always 200 with a tag that differs from the stored one only
			// in its weak prefix and -gzip suffix.
			if r.Header.Get("If-None-Match") != "" {
				w.Header().Set("ETag", `"h1"`)
			} else {
				w.Header().Set("ETag", `W/"h1-gzip"`)
			}
			_, _ = io.WriteString(w, "0.0.0.0 example-agent.ai\n")
		case r.URL.Path == prefix+"README.txt":
			_, _ = io.WriteString(w, "no etag here\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) client(t *testing.T, token string) *Client {
	t.Helper()
	c, err := New(token, WithBaseURL(fs.srv.URL), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (fs *feedServer) lastINM() string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.inm[len(fs.inm)-1]
}

func TestDownloadAndUserAgent(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	body, err := c.Download(context.Background(), "domains.txt")
	if err != nil || string(body) != "example-agent.ai\n" {
		t.Fatalf("Download = %q, %v", body, err)
	}
	if fs.agents[0] != "aiagentblocklist-go/1.0.0 (+https://www.aiagentblocklist.com)" {
		t.Fatalf("User-Agent = %q", fs.agents[0])
	}
	c2, _ := New(testToken, WithBaseURL(fs.srv.URL), WithUserAgent("sidecar/2"))
	if _, err := c2.Download(context.Background(), "domains.txt"); err != nil {
		t.Fatal(err)
	}
	if fs.agents[1] != "sidecar/2" {
		t.Fatalf("custom User-Agent = %q", fs.agents[1])
	}
}

func TestStatusMapping(t *testing.T) {
	fs := newFeedServer(t)
	ctx := context.Background()

	_, err := fs.client(t, testToken).Download(ctx, "missing.txt")
	var e *Error
	if !errors.Is(err, ErrNotFound) || !errors.As(err, &e) || e.Status != 404 {
		t.Fatalf("404 mapping: %v", err)
	}
	_, err = fs.client(t, strings.Repeat("Z", 32)).Download(ctx, "domains.txt")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	_, err = fs.client(t, strings.Repeat("P", 32)).Download(ctx, "domains.txt")
	if !errors.Is(err, ErrAccessEnded) || !errors.As(err, &e) || e.Status != 403 {
		t.Fatalf("403 mapping: %v", err)
	}
	_, err = fs.client(t, strings.Repeat("E", 32)).Download(ctx, "domains.txt")
	if !errors.Is(err, ErrHTTP) || !errors.As(err, &e) || e.Status != 500 {
		t.Fatalf("500 mapping: %v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("E", 32)) {
		t.Fatal("error message leaks the token")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("500 must not match ErrNotFound")
	}
}

func TestNetworkErrorIsWrapped(t *testing.T) {
	fs := newFeedServer(t)
	url := fs.srv.URL
	fs.srv.Close()
	c, _ := New(testToken, WithBaseURL(url), WithTimeout(2*time.Second))
	_, err := c.Download(context.Background(), "domains.txt")
	var e *Error
	if !errors.As(err, &e) || e.Status != 0 || e.Kind != nil || e.Err == nil {
		t.Fatalf("network error = %#v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("network error leaks the token")
	}
}

func TestContextCancel(t *testing.T) {
	fs := newFeedServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fs.client(t, testToken).Download(ctx, "domains.txt")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}

func TestDownloadToETagSidecar(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	ctx := context.Background()
	path := filepath.Join(tempDir(t), "nested", "domains.txt")

	// 1. First download: 200, file and sidecar written.
	changed, err := c.DownloadTo(ctx, "domains.txt", path)
	if err != nil || !changed {
		t.Fatalf("first DownloadTo = %v, %v", changed, err)
	}
	if fs.lastINM() != "" {
		t.Fatal("first request must not be conditional")
	}
	if b, _ := os.ReadFile(path + ".etag"); string(b) != `W/"v1-gzip"` {
		t.Fatalf("sidecar = %q", b)
	}

	// 2. Unchanged: If-None-Match carries the stored tag, 304, false.
	before, _ := os.Stat(path)
	changed, err = c.DownloadTo(ctx, "domains.txt", path)
	if err != nil || changed {
		t.Fatalf("second DownloadTo = %v, %v", changed, err)
	}
	if fs.lastINM() != `W/"v1-gzip"` {
		t.Fatalf("If-None-Match = %q", fs.lastINM())
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("file touched on 304")
	}

	// 3. New content and tag: 200, file replaced, sidecar updated.
	fs.mu.Lock()
	fs.domainsV, fs.domainsET = "example-agent.ai\nsample-browser.app\n", `"v2"`
	fs.mu.Unlock()
	changed, err = c.DownloadTo(ctx, "domains.txt", path)
	if err != nil || !changed {
		t.Fatalf("third DownloadTo = %v, %v", changed, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "example-agent.ai\nsample-browser.app\n" {
		t.Fatalf("file = %q", b)
	}
	if b, _ := os.ReadFile(path + ".etag"); string(b) != `"v2"` {
		t.Fatalf("sidecar = %q", b)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, de := range entries {
		if strings.Contains(de.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", de.Name())
		}
	}
}

func TestDownloadToBareETagOn200(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	path := filepath.Join(tempDir(t), "hosts.txt")
	if changed, err := c.DownloadTo(context.Background(), "hosts.txt", path); err != nil || !changed {
		t.Fatalf("first = %v, %v", changed, err)
	}
	// Overwrite the local copy to prove the second call does not rewrite it.
	if err := os.WriteFile(path, []byte("local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := c.DownloadTo(context.Background(), "hosts.txt", path)
	if err != nil || changed {
		t.Fatalf("200 with the same bare ETag must report unchanged: %v, %v", changed, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "local\n" {
		t.Fatal("file rewritten although the bare ETag matched")
	}
}

func TestDownloadToMissingFileIgnoresSidecar(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	dir := tempDir(t)
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path+".etag", []byte(`W/"v1-gzip"`), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := c.DownloadTo(context.Background(), "domains.txt", path)
	if err != nil || !changed || fs.lastINM() != "" {
		t.Fatalf("stale sidecar without file: %v, %v, INM=%q", changed, err, fs.lastINM())
	}
}

func TestDownloadToWithoutETag(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	path := filepath.Join(tempDir(t), "README.txt")
	for i := 0; i < 2; i++ {
		changed, err := c.DownloadTo(context.Background(), "README.txt", path)
		if err != nil || !changed {
			t.Fatalf("call %d = %v, %v", i, changed, err)
		}
		if fs.lastINM() != "" {
			t.Fatal("no ETag stored, so no If-None-Match expected")
		}
	}
	if b, err := os.ReadFile(path + ".etag"); err != nil || len(b) != 0 {
		t.Fatalf("sidecar should exist and be empty: %q, %v", b, err)
	}
}

func TestDownloadToErrorKeepsFile(t *testing.T) {
	fs := newFeedServer(t)
	path := filepath.Join(tempDir(t), "domains.txt")
	if err := os.WriteFile(path, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := fs.client(t, strings.Repeat("P", 32)).DownloadTo(context.Background(), "domains.txt", path)
	if !errors.Is(err, ErrAccessEnded) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "keep\n" {
		t.Fatal("existing file changed on error")
	}
}

func TestSync(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	dir := tempDir(t)
	res, err := c.Sync(context.Background(), dir, "domains.txt", "aab_full.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res["domains.txt"] || !res["aab_full.json"] {
		t.Fatalf("first sync = %v", res)
	}
	res, err = c.Sync(context.Background(), dir, "domains.txt", "aab_full.json")
	if err != nil || res["domains.txt"] || res["aab_full.json"] {
		t.Fatalf("second sync = %v, %v", res, err)
	}
	bl, err := BlocklistFromFile(filepath.Join(dir, "aab_full.json"))
	if err != nil || bl.CheckDomain("x.sample-browser.app") == nil {
		t.Fatalf("synced JSON unusable: %v", err)
	}
	// Default names: the first unknown file stops the run with ErrNotFound.
	res, err = c.Sync(context.Background(), tempDir(t))
	if !errors.Is(err, ErrNotFound) || len(res) != 0 {
		t.Fatalf("default sync against the test server = %v, %v", res, err)
	}
}

func TestLoadBlocklistAndOpen(t *testing.T) {
	fs := newFeedServer(t)
	c := fs.client(t, testToken)
	bl, err := c.LoadBlocklist(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bl.CheckExtension("abcdefghijklmnopabcdefghijklmnop") == nil {
		t.Fatal("loaded blocklist misses the extension")
	}
	rc, err := c.Open(context.Background(), "domains.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	if string(b) != "example-agent.ai\n" {
		t.Fatalf("Open body = %q", b)
	}
}

func TestBareETag(t *testing.T) {
	for in, want := range map[string]string{
		`"abc"`:          "abc",
		`W/"abc"`:        "abc",
		`w/"abc-gzip"`:   "abc",
		`"abc-gzip"`:     "abc",
		` "abc" `:        "abc",
		`abc`:            "abc",
		`"abc-gzipped"`:  "abc-gzipped",
		`W/"5f-12-gzip"`: "5f-12",
	} {
		if got := BareETag(in); got != want {
			t.Errorf("BareETag(%q) = %q, want %q", in, got, want)
		}
	}
}
