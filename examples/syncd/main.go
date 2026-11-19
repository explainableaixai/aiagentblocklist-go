// Command syncd is a small sidecar: it keeps a local copy of the AI Agent
// Blocklist files fresh and answers lookups on a loopback HTTP port.
//
//	AIAGENTBLOCKLIST_TOKEN=... go run ./examples/syncd -dir /var/lib/aab -every 6h
//	curl 'http://127.0.0.1:8089/check?q=https://api.example-agent.ai/v1'
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	aab "github.com/explainableaixai/aiagentblocklist-go"
)

func main() {
	dir := flag.String("dir", "aab-feed", "directory for the feed files")
	every := flag.Duration("every", 6*time.Hour, "time between sync runs")
	listen := flag.String("listen", "127.0.0.1:8089", "address for /check and /healthz")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := aab.New("") // token from AIAGENTBLOCKLIST_TOKEN
	if err != nil {
		log.Fatal(err)
	}

	var current atomic.Pointer[aab.Blocklist]
	jsonPath := filepath.Join(*dir, "aab_full.json")
	if bl, err := aab.BlocklistFromFile(jsonPath); err == nil {
		current.Store(bl) // start serving from the last good copy
	}

	refresh := func() {
		res, err := client.Sync(ctx, *dir)
		switch {
		case errors.Is(err, aab.ErrAccessEnded):
			log.Printf("subscription ended or paused; keeping the files on disk")
			return
		case err != nil:
			log.Printf("sync failed, keeping the old copy: %v", err)
			return
		}
		if res["aab_full.json"] || current.Load() == nil {
			bl, err := aab.BlocklistFromFile(jsonPath)
			if err != nil {
				log.Printf("parse failed: %v", err)
				return
			}
			current.Store(bl)
			log.Printf("loaded version %s with %d entries", bl.Version, len(bl.Entries))
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		bl := current.Load()
		if bl == nil {
			http.Error(w, "feed not loaded yet", http.StatusServiceUnavailable)
			return
		}
		e := bl.Check(r.URL.Query().Get("q"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"listed": e != nil, "entry": e})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if current.Load() == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	refresh()
	tick := time.NewTicker(*every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
			return
		case <-tick.C:
			refresh()
		}
	}
}
