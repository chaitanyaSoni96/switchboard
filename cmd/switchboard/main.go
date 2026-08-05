// Command switchboard serves a single page linking to every HTTP service
// listening on this machine, gated on where the request came from.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"switchboard/internal/discover"
	"switchboard/internal/web"
)

func main() {
	port := flag.Int("port", 8090, "port to listen on")
	trustForwarded := flag.Bool("trust-forwarded", false,
		"honour X-Forwarded-For when classifying request origin (only safe behind a proxy you control)")
	flag.Parse()

	if *port < 1 || *port > 65535 {
		log.Fatalf("switchboard: --port %d out of range", *port)
	}

	reg := discover.New(*port)
	srv := &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(*port)),
		Handler:           web.NewServer(reg, *trustForwarded),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("switchboard listening on http://localhost:%d (trust-forwarded=%v)", *port, *trustForwarded)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("switchboard: %v", err)
	}
}
