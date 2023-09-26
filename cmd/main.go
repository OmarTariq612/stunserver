package main

import (
	"log"
	"os"
	"time"

	"github.com/OmarTariq612/stunserver"
)

func main() {
	var addr string

	if len(os.Args) < 2 {
		addr = "0.0.0.0:3478"
	} else {
		addr = os.Args[1]
	}

	server, err := stunserver.NewServer(addr, stunserver.WithoutResponseOrigin, stunserver.WithReadTimeoutDuration(10*time.Second))
	if err != nil {
		log.Fatal(err)
	}

	if err = server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
