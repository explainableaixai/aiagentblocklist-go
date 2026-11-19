// Command blockproxy is a minimal forward HTTP proxy that refuses requests
// and CONNECT tunnels to hosts on the AI Agent Blocklist. It shows where a
// lookup fits in a proxy; it is not a hardened production proxy.
//
//	go run ./examples/blockproxy -feed /var/lib/aab/aab_full.json -listen 127.0.0.1:3128
//	curl -x http://127.0.0.1:3128 https://api.example-agent.ai/   # refused with 403
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	aab "github.com/explainableaixai/aiagentblocklist-go"
)

func main() {
	feed := flag.String("feed", "aab-feed/aab_full.json", "local aab_full.json kept fresh by syncd or cron")
	listen := flag.String("listen", "127.0.0.1:3128", "proxy listen address")
	flag.Parse()

	bl, err := aab.BlocklistFromFile(*feed)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("blocking %d domains from version %s", len(bl.Domains()), bl.Version)

	upstream := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 30 * time.Second}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if r.Method != http.MethodConnect && r.URL.Host != "" {
			host = r.URL.Host
		}
		if e := bl.CheckDomain(host); e != nil {
			log.Printf("refused %s %s (%s, %s)", r.Method, host, e.AgentType, e.Ident)
			http.Error(w, "blocked by policy: AI agent domain", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodConnect {
			tunnel(w, r)
			return
		}
		if !r.URL.IsAbs() {
			http.Error(w, "this is a proxy; send absolute URLs", http.StatusBadRequest)
			return
		}
		r.RequestURI = ""
		r.Header.Del("Proxy-Connection")
		resp, err := upstream.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func tunnel(w http.ResponseWriter, r *http.Request) {
	dst, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		dst.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	src, buf, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	_, _ = src.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		defer dst.Close()
		if buf.Reader.Buffered() > 0 {
			_, _ = io.CopyN(dst, buf, int64(buf.Reader.Buffered()))
		}
		_, _ = io.Copy(dst, src)
	}()
	go func() {
		defer src.Close()
		_, _ = io.Copy(src, dst)
	}()
}
