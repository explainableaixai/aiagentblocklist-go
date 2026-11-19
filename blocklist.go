package aiagentblocklist

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Entry is one row of the feed. All fields are strings, as in aab_full.csv.
type Entry struct {
	ToolName    string `json:"tool_name"`
	ToolDomain  string `json:"tool_domain"`
	Category    string `json:"category"`
	Subcategory string `json:"subcategory"`
	AgentType   string `json:"agent_type"`
	Kind        string `json:"kind"`
	Ident       string `json:"ident"`
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	RiskGrade   string `json:"risk_grade"`
}

// Ecosystem names accepted by CheckPackage.
const (
	EcosystemNPM  = "npm"
	EcosystemPyPI = "pypi"
)

var (
	extensionKinds = map[string]bool{
		"chrome_ext": true, "edge_ext": true, "firefox_ext": true,
		"vscode_ext": true, "openvsx_ext": true, "jetbrains_plugin": true,
	}
	processKinds = map[string]bool{"process_cli": true, "process_mac": true, "process_win": true}
	pep503Re     = regexp.MustCompile(`[-_.]+`)
)

// Blocklist is a parsed aab_full.json with lookup maps built once at load
// time. It is read-only after construction and safe for concurrent use, so
// a daemon can swap a fresh *Blocklist in with sync/atomic while requests
// keep reading the old one.
type Blocklist struct {
	Product string
	Version string
	Counts  map[string]int
	Columns []string
	Entries []Entry

	domainIdx  map[string]*Entry
	extIdx     map[string]*Entry
	procIdx    map[string]*Entry
	npmIdx     map[string]*Entry
	pypiIdx    map[string]*Entry
	identIdx   map[string]*Entry
	identLower map[string]*Entry
	domainList []string
	agentTypes []string
	kinds      []string
}

type rawFeed struct {
	Product string                     `json:"product"`
	Version string                     `json:"version"`
	Counts  map[string]json.RawMessage `json:"counts"`
	Columns []string                   `json:"columns"`
	Entries []Entry                    `json:"entries"`
}

// ReadBlocklist parses aab_full.json from any io.Reader: an open file, a
// response body from Client.Open, a gzip.Reader or a bytes.Buffer.
func ReadBlocklist(r io.Reader) (*Blocklist, error) {
	var raw rawFeed
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return nil, &Error{Message: "aab_full.json could not be parsed", Err: err}
	}
	return newBlocklist(raw), nil
}

// BlocklistFromJSON parses the contents of aab_full.json.
func BlocklistFromJSON(data []byte) (*Blocklist, error) {
	return ReadBlocklist(bytes.NewReader(data))
}

// BlocklistFromFile reads and parses a local copy of aab_full.json, for
// example one kept fresh by Client.DownloadTo or Client.Sync.
func BlocklistFromFile(path string) (*Blocklist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &Error{Message: "cannot open " + path, Err: err}
	}
	defer f.Close()
	return ReadBlocklist(f)
}

func newBlocklist(raw rawFeed) *Blocklist {
	b := &Blocklist{
		Product:    raw.Product,
		Version:    raw.Version,
		Counts:     map[string]int{},
		Columns:    raw.Columns,
		Entries:    raw.Entries,
		domainIdx:  map[string]*Entry{},
		extIdx:     map[string]*Entry{},
		procIdx:    map[string]*Entry{},
		npmIdx:     map[string]*Entry{},
		pypiIdx:    map[string]*Entry{},
		identIdx:   map[string]*Entry{},
		identLower: map[string]*Entry{},
	}
	for k, v := range raw.Counts {
		var n int
		if json.Unmarshal(v, &n) == nil {
			b.Counts[k] = n
		}
	}
	types := map[string]bool{}
	kinds := map[string]bool{}
	put := func(m map[string]*Entry, key string, e *Entry) {
		if key == "" {
			return
		}
		if _, ok := m[key]; !ok {
			m[key] = e
		}
	}
	for i := range b.Entries {
		e := &b.Entries[i]
		ident := strings.TrimSpace(e.Ident)
		lower := strings.ToLower(ident)
		if e.AgentType != "" {
			types[e.AgentType] = true
		}
		if e.Kind != "" {
			kinds[e.Kind] = true
		}
		put(b.identIdx, ident, e)
		put(b.identLower, lower, e)
		switch {
		case e.Kind == "domain":
			d := strings.TrimRight(lower, ".")
			if _, seen := b.domainIdx[d]; !seen && d != "" {
				b.domainList = append(b.domainList, d)
			}
			put(b.domainIdx, d, e)
		case extensionKinds[e.Kind]:
			put(b.extIdx, lower, e)
		case processKinds[e.Kind]:
			put(b.procIdx, lower, e)
			if strings.HasSuffix(lower, ".exe") {
				put(b.procIdx, strings.TrimSuffix(lower, ".exe"), e)
			}
		case e.Kind == "npm":
			put(b.npmIdx, lower, e)
		case e.Kind == "pypi":
			put(b.pypiIdx, NormalizePyPI(ident), e)
		}
	}
	b.agentTypes = sortedKeys(types)
	b.kinds = sortedKeys(kinds)
	return b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NormalizeHost turns a URL or a host into a bare lowercase host name. It
// strips the scheme, user info, port, path, query and fragment and drops a
// trailing dot. It returns "" when nothing is left.
func NormalizeHost(s string) string {
	h := strings.TrimSpace(s)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	} else if strings.HasPrefix(h, "//") {
		h = h[2:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			h = h[1:i]
		} else {
			h = h[1:]
		}
	} else if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSpace(h))
	return strings.TrimRight(h, ".")
}

// NormalizePyPI applies the PEP 503 rule: lowercase, and every run of
// "-", "_" and "." becomes a single "-".
func NormalizePyPI(name string) string {
	return pep503Re.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// CheckDomain returns the listed entry for a host or URL, or nil. The host
// matches when it or any parent domain is listed: api.example-agent.ai
// matches example-agent.ai, while notexample-agent.ai does not. Only
// entries of kind "domain" are considered.
func (b *Blocklist) CheckDomain(hostOrURL string) *Entry {
	h := NormalizeHost(hostOrURL)
	for h != "" {
		if e, ok := b.domainIdx[h]; ok {
			return e
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return nil
}

// CheckExtension matches a browser extension ID or an IDE plugin ID,
// ignoring case. It covers Chrome, Edge and Firefox extensions, VS Code and
// Open VSX extensions and JetBrains plugins.
func (b *Blocklist) CheckExtension(id string) *Entry {
	return b.extIdx[strings.ToLower(strings.TrimSpace(id))]
}

// CheckProcess matches a process or command name, ignoring case and any
// directory part. "agent.exe" and "agent" match each other.
func (b *Blocklist) CheckProcess(name string) *Entry {
	n := strings.TrimSpace(name)
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	n = strings.ToLower(strings.TrimSpace(n))
	if n == "" {
		return nil
	}
	if e, ok := b.procIdx[n]; ok {
		return e
	}
	if strings.HasSuffix(n, ".exe") {
		return b.procIdx[strings.TrimSuffix(n, ".exe")]
	}
	return nil
}

// CheckPackage matches a package name in the "npm" or "pypi" ecosystem.
// npm names compare in lowercase; PyPI names compare after PEP 503
// normalisation. It returns nil for any other ecosystem.
func (b *Blocklist) CheckPackage(ecosystem, name string) *Entry {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case EcosystemNPM:
		return b.npmIdx[strings.ToLower(strings.TrimSpace(name))]
	case EcosystemPyPI:
		return b.pypiIdx[NormalizePyPI(name)]
	}
	return nil
}

// Check matches any identifier: first as a host or URL with parent domain
// matching, then as an exact identifier of any kind, then ignoring case.
func (b *Blocklist) Check(identifier string) *Entry {
	if e := b.CheckDomain(identifier); e != nil {
		return e
	}
	id := strings.TrimSpace(identifier)
	if e, ok := b.identIdx[id]; ok {
		return e
	}
	return b.identLower[strings.ToLower(id)]
}

// Filter returns the entries that match every non-empty argument, in file
// order. Comparisons ignore case.
func (b *Blocklist) Filter(agentType, kind, riskGrade string) []Entry {
	var out []Entry
	for _, e := range b.Entries {
		if agentType != "" && !strings.EqualFold(e.AgentType, agentType) {
			continue
		}
		if kind != "" && !strings.EqualFold(e.Kind, kind) {
			continue
		}
		if riskGrade != "" && !strings.EqualFold(e.RiskGrade, riskGrade) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Domains returns the distinct listed domains, lowercase, in file order.
func (b *Blocklist) Domains() []string {
	return append([]string(nil), b.domainList...)
}

// AgentTypes returns the distinct agent_type values, sorted.
func (b *Blocklist) AgentTypes() []string {
	return append([]string(nil), b.agentTypes...)
}

// Kinds returns the distinct kind values, sorted.
func (b *Blocklist) Kinds() []string {
	return append([]string(nil), b.kinds...)
}
