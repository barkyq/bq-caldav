package main

import (
	"flag"
	"log"
	"net/http"

	"bq-caldav/core"
	"bq-caldav/fsbackend"
)

var backend_location_flag = flag.String("backend", "backend", "backend location")
var listen_address_flag = flag.String("listen", "127.0.0.1:8282", "listen address")

func main() {
	flag.Parse()
	wrapper := &core.Wrapper{
		Handler: &core.Handler{
			Backend: fsbackend.NewBackend(*backend_location_flag),
		},
	}

	log.Printf("Starting CalDAV server on %s", *listen_address_flag)
	log.Fatal(http.ListenAndServe(*listen_address_flag, wrapper))
}
