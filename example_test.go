package aiagentblocklist_test

import (
	"fmt"
	"strings"

	aab "github.com/explainableaixai/aiagentblocklist-go"
)

const sampleFeed = `{"product":"AI Agent Blocklist","version":"demo","counts":{"domains":1},
"columns":["tool_name","tool_domain","category","subcategory","agent_type","kind","ident","name","platform","risk_grade"],
"entries":[
 {"tool_name":"Example Agent","tool_domain":"example-agent.ai","category":"Agents","subcategory":"Agents","agent_type":"Autonomous agent","kind":"domain","ident":"example-agent.ai","name":"Example Agent","platform":"Network","risk_grade":"Moderate"},
 {"tool_name":"Example Agent","tool_domain":"example-agent.ai","category":"Agents","subcategory":"Agents","agent_type":"Autonomous agent","kind":"process_win","ident":"SampleAgent.exe","name":"Example Agent","platform":"Windows","risk_grade":"Moderate"}
]}`

func ExampleReadBlocklist() {
	bl, err := aab.ReadBlocklist(strings.NewReader(sampleFeed))
	if err != nil {
		panic(err)
	}
	fmt.Println(bl.Version, len(bl.Entries))
	// Output: demo 2
}

func ExampleBlocklist_CheckDomain() {
	bl, _ := aab.BlocklistFromJSON([]byte(sampleFeed))
	for _, in := range []string{
		"https://API.example-agent.ai:443/v1?task=1",
		"notexample-agent.ai",
	} {
		if e := bl.CheckDomain(in); e != nil {
			fmt.Println(in, "->", e.Ident)
		} else {
			fmt.Println(in, "-> not listed")
		}
	}
	// Output:
	// https://API.example-agent.ai:443/v1?task=1 -> example-agent.ai
	// notexample-agent.ai -> not listed
}

func ExampleBlocklist_CheckProcess() {
	bl, _ := aab.BlocklistFromJSON([]byte(sampleFeed))
	fmt.Println(bl.CheckProcess(`C:\Apps\sampleagent`) != nil)
	// Output: true
}

func ExampleNormalizePyPI() {
	fmt.Println(aab.NormalizePyPI("Demo_MCP.Server"))
	// Output: demo-mcp-server
}
