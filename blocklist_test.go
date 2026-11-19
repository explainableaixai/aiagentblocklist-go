package aiagentblocklist

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T) *Blocklist {
	t.Helper()
	bl, err := BlocklistFromFile("testdata/aab_full.json")
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return bl
}

func TestFixtureMetadata(t *testing.T) {
	bl := fixture(t)
	if bl.Product != "AI Agent Blocklist" || bl.Version != "test-1" {
		t.Fatalf("product/version = %q/%q", bl.Product, bl.Version)
	}
	if len(bl.Entries) != 16 {
		t.Fatalf("entries = %d, want 16", len(bl.Entries))
	}
	if bl.Counts["domains"] != 3 || bl.Counts["entries"] != 16 {
		t.Fatalf("counts = %v", bl.Counts)
	}
	if len(bl.Columns) != 10 || bl.Columns[6] != "ident" {
		t.Fatalf("columns = %v", bl.Columns)
	}
}

func TestReadBlocklistFromReader(t *testing.T) {
	data, err := os.ReadFile("testdata/aab_full.json")
	if err != nil {
		t.Fatal(err)
	}
	bl, err := ReadBlocklist(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if bl.CheckDomain("example-agent.ai") == nil {
		t.Fatal("reader-based load lost the domain index")
	}
	if _, err := BlocklistFromJSON([]byte("{not json")); err == nil {
		t.Fatal("broken JSON must fail")
	}
}

func TestCountsIgnoreNonIntegers(t *testing.T) {
	bl, err := BlocklistFromJSON([]byte(`{"product":"x","version":"1","counts":{"domains":2,"note":"text"},"entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if bl.Counts["domains"] != 2 || len(bl.Counts) != 1 {
		t.Fatalf("counts = %v", bl.Counts)
	}
}

func TestCheckDomainSuffix(t *testing.T) {
	bl := fixture(t)
	cases := map[string]string{
		"example-agent.ai":            "example-agent.ai",
		"api.example-agent.ai":        "example-agent.ai",
		"a.b.c.example-agent.ai":      "example-agent.ai",
		"sample-browser.app":          "sample-browser.app",
		"cdn.demo-mcp-server.dev":     "demo-mcp-server.dev",
		"notexample-agent.ai":         "",
		"example-agent.ai.other.test": "",
		"example-agent":               "",
		"ai":                          "",
		"":                            "",
	}
	for in, want := range cases {
		e := bl.CheckDomain(in)
		got := ""
		if e != nil {
			got = e.Ident
		}
		if got != want {
			t.Errorf("CheckDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckDomainNormalisesURLs(t *testing.T) {
	bl := fixture(t)
	for _, in := range []string{
		"https://api.example-agent.ai/v1/run?x=1#frag",
		"HTTPS://USER:pw@API.Example-Agent.AI:8443/path",
		"http://example-agent.ai.",
		"  example-agent.ai:443  ",
		"//cdn.example-agent.ai/lib.js",
		"wss://socket.example-agent.ai",
		"api.example-agent.ai/path?q=1",
	} {
		if e := bl.CheckDomain(in); e == nil || e.Ident != "example-agent.ai" {
			t.Errorf("CheckDomain(%q) = %v", in, e)
		}
	}
	if got := NormalizeHost("https://u:p@Host.Example.:8080/a?b#c"); got != "host.example" {
		t.Errorf("NormalizeHost = %q", got)
	}
	if got := NormalizeHost("[::1]:8080"); got != "::1" {
		t.Errorf("NormalizeHost IPv6 = %q", got)
	}
}

func TestCheckDomainIgnoresOtherKinds(t *testing.T) {
	bl := fixture(t)
	if e := bl.CheckDomain("com.example.agentbrowser"); e != nil {
		t.Fatalf("bundle ID matched as a domain: %v", e)
	}
	if e := bl.CheckDomain("demo-mcp-server"); e != nil {
		t.Fatalf("npm name matched as a domain: %v", e)
	}
}

func TestCheckExtension(t *testing.T) {
	bl := fixture(t)
	tests := map[string]string{
		"abcdefghijklmnopabcdefghijklmnop":   "chrome_ext",
		"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP":   "chrome_ext",
		" ponmlkjihgfedcbaponmlkjihgfedcba ": "edge_ext",
		"Agent@Example-Agent.ai":             "firefox_ext",
		"exampleagent.agent-helper":          "vscode_ext",
		"com.example.agent.jetbrains":        "jetbrains_plugin",
	}
	for in, kind := range tests {
		e := bl.CheckExtension(in)
		if e == nil || e.Kind != kind {
			t.Errorf("CheckExtension(%q) = %v, want kind %s", in, e, kind)
		}
	}
	if bl.CheckExtension("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != nil {
		t.Error("unknown extension matched")
	}
	if bl.CheckExtension("com.example.agentbrowser") != nil {
		t.Error("bundle ID matched as an extension")
	}
}

func TestCheckProcess(t *testing.T) {
	bl := fixture(t)
	for _, in := range []string{
		"SampleAgent.exe", "sampleagent.exe", "SAMPLEAGENT", "sampleagent",
		`C:\Program Files\Example\SampleAgent.exe`, "/usr/local/bin/demo-agent",
		"demo-agent", "DEMO-AGENT.EXE", "sample browser",
	} {
		if bl.CheckProcess(in) == nil {
			t.Errorf("CheckProcess(%q) = nil", in)
		}
	}
	for _, in := range []string{"", "agent", "sampleagent.exe.bak", "demo-agent.sh"} {
		if e := bl.CheckProcess(in); e != nil {
			t.Errorf("CheckProcess(%q) = %v, want nil", in, e)
		}
	}
}

func TestCheckPackage(t *testing.T) {
	bl := fixture(t)
	if e := bl.CheckPackage("npm", "Demo-MCP-Server"); e == nil || e.Kind != "npm" {
		t.Errorf("npm lowercase match failed: %v", e)
	}
	if e := bl.CheckPackage("NPM", "@example/agent-cli"); e == nil {
		t.Error("scoped npm package not found")
	}
	for _, in := range []string{"demo-mcp-server", "Demo_MCP.Server", "DEMO__mcp..server", "demo.mcp_server"} {
		if e := bl.CheckPackage("pypi", in); e == nil || e.Kind != "pypi" {
			t.Errorf("CheckPackage(pypi, %q) = %v", in, e)
		}
	}
	if bl.CheckPackage("npm", "demo_mcp_server") != nil {
		t.Error("npm must not use PEP 503 rules")
	}
	if bl.CheckPackage("cargo", "demo-mcp-server") != nil {
		t.Error("unknown ecosystem must return nil")
	}
	if got := NormalizePyPI("Foo__Bar..baz-_-qux"); got != "foo-bar-baz-qux" {
		t.Errorf("NormalizePyPI = %q", got)
	}
}

func TestCheckOrder(t *testing.T) {
	bl := fixture(t)
	if e := bl.Check("https://www.sample-browser.app/download"); e == nil || e.Kind != "domain" {
		t.Errorf("Check URL = %v", e)
	}
	if e := bl.Check("com.example.agentbrowser"); e == nil || e.Kind != "mac_bundle_id" {
		t.Errorf("Check bundle ID = %v", e)
	}
	if e := bl.Check("examplecorp.agentdesktop"); e == nil || e.Kind != "winget" {
		t.Errorf("Check winget lower = %v", e)
	}
	if e := bl.Check("agent@example-agent.ai"); e == nil || e.Kind != "domain" {
		t.Errorf("domain matching must come first: %v", e)
	}
	if bl.Check("nothing-listed.example") != nil {
		t.Error("unexpected match")
	}
}

func TestFilterAndLists(t *testing.T) {
	bl := fixture(t)
	if n := len(bl.Filter("", "domain", "")); n != 3 {
		t.Errorf("domains via Filter = %d", n)
	}
	if n := len(bl.Filter("mcp server", "", "")); n != 3 {
		t.Errorf("MCP server entries = %d", n)
	}
	high := bl.Filter("", "", "High")
	if len(high) != 3 {
		t.Errorf("High entries = %d", len(high))
	}
	if n := len(bl.Filter("Coding agent", "npm", "Low")); n != 1 {
		t.Errorf("combined filter = %d", n)
	}
	if n := len(bl.Filter("", "", "")); n != 16 {
		t.Errorf("empty filter = %d", n)
	}
	if got := bl.Domains(); !reflect.DeepEqual(got, []string{"example-agent.ai", "sample-browser.app", "demo-mcp-server.dev"}) {
		t.Errorf("Domains = %v", got)
	}
	wantTypes := []string{"AI browser", "Autonomous agent", "Browser agent", "Coding agent", "MCP server", "Personal AI assistant"}
	if got := bl.AgentTypes(); !reflect.DeepEqual(got, wantTypes) {
		t.Errorf("AgentTypes = %v", got)
	}
	kinds := bl.Kinds()
	if len(kinds) != 13 || kinds[0] != "chrome_ext" {
		t.Errorf("Kinds = %v", kinds)
	}
	// Returned slices are copies.
	kinds[0] = "changed"
	if bl.Kinds()[0] != "chrome_ext" {
		t.Error("Kinds leaks internal state")
	}
}
