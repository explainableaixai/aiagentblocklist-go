// Command checkfile reads aab_full.json from a file or from stdin (any
// io.Reader works) and checks identifiers offline, or prints a Chrome
// ExtensionInstallBlocklist policy for one agent type.
//
//	go run ./examples/checkfile -feed aab_full.json api.example-agent.ai SampleAgent.exe
//	cat aab_full.json | go run ./examples/checkfile -policy "Browser agent"
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	aab "github.com/explainableaixai/aiagentblocklist-go"
)

func main() {
	feed := flag.String("feed", "-", "path to aab_full.json, or - for stdin")
	policy := flag.String("policy", "", "print a Chrome extension policy for this agent type instead of checking")
	flag.Parse()

	var r io.Reader = os.Stdin
	if *feed != "-" {
		f, err := os.Open(*feed)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		r = f
	}
	bl, err := aab.ReadBlocklist(r)
	if err != nil {
		log.Fatal(err)
	}

	if *policy != "" {
		ids := []string{}
		for _, e := range bl.Filter(*policy, "chrome_ext", "") {
			ids = append(ids, e.Ident)
		}
		out, _ := json.MarshalIndent(map[string][]string{"ExtensionInstallBlocklist": ids}, "", "  ")
		fmt.Println(string(out))
		return
	}

	exit := 0
	for _, id := range flag.Args() {
		if e := bl.Check(id); e != nil {
			fmt.Printf("LISTED  %-40s kind=%s type=%q tool=%q\n", id, e.Kind, e.AgentType, e.ToolName)
			exit = 1
		} else {
			fmt.Printf("clear   %s\n", id)
		}
	}
	os.Exit(exit)
}
