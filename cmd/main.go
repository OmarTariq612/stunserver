package main

import (
	"net/netip"
	"os"

	"github.com/OmarTariq612/stunserver"
)

func main() {
	var addr string

	if len(os.Args) < 2 {
		addr = "0.0.0.0:3478"
	} else {
		addr = os.Args[1]
	}

	server := stunserver.NewServer(stunserver.WithSimpleMode(netip.MustParseAddrPort(addr)))
	server.ListenAndServe()
}
