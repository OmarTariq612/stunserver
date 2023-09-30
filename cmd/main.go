package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/OmarTariq612/stunserver"
)

func main() {
	config, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch config.mode {
	case simple:
		addrPort := netip.MustParseAddrPort(config.hosts[0].String() + ":" + strconv.Itoa(int(config.ports[0])))
		server := stunserver.NewServer(stunserver.WithSimpleMode(addrPort))
		if err := server.ListenAndServe(); err != nil {
			fmt.Println(err)
		}
	case full:
		server := stunserver.NewServer(stunserver.WithFullMode(
			config.hosts[0],
			config.hosts[1],
			config.ports[0],
			config.ports[1],
		))
		if err := server.ListenAndServe(); err != nil {
			fmt.Println(err)
		}
	}
}

type mode byte

const (
	simple mode = iota
	full
)

type config struct {
	mode  mode
	hosts [2]netip.Addr
	ports [2]uint16
}

func validPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port: %d, the acceptable range is [0:65535]", port)
	}
	return nil
}

func parseArgs(args []string) (*config, error) {
	simpleModeflags := flag.NewFlagSet("simple", flag.ExitOnError)
	simpleHost := simpleModeflags.String("host", "0.0.0.0", "host")
	simplePort := simpleModeflags.Int("port", stunserver.DefaultPort, "port")

	fullModeflags := flag.NewFlagSet("full", flag.ExitOnError)
	fullHost := fullModeflags.String("host", "", "primary host")
	fullPort := fullModeflags.Int("port", 0, "primary port")
	altFullHost := fullModeflags.String("alt-host", "", "alternative host")
	altFullPort := fullModeflags.Int("alt-port", 0, "alternative port")

	switch {
	case len(os.Args) < 2:
		return &config{mode: simple, hosts: [2]netip.Addr{netip.MustParseAddr("0.0.0.0")}, ports: [2]uint16{stunserver.DefaultPort}}, nil

	case os.Args[1] == "simple":
		simpleModeflags.Parse(os.Args[2:])
		host, err := netip.ParseAddr(*simpleHost)
		if err != nil {
			return nil, err
		}
		if *simplePort < 0 || *simplePort > 65535 {
			return nil, fmt.Errorf("invalid port: %d, the acceptable range is [0:65535]", *simplePort)
		}
		return &config{mode: simple, hosts: [2]netip.Addr{host}, ports: [2]uint16{uint16(*simplePort)}}, nil

	case os.Args[1] == "full":
		fullModeflags.Parse(os.Args[2:])
		host, err := netip.ParseAddr(*fullHost)
		if err != nil {
			return nil, err
		}
		altHost, err := netip.ParseAddr(*altFullHost)
		if err != nil {
			return nil, err
		}
		if err = validPort(*fullPort); err != nil {
			return nil, err
		}
		if err = validPort(*altFullPort); err != nil {
			return nil, err
		}

		return &config{mode: full, hosts: [2]netip.Addr{host, altHost}, ports: [2]uint16{uint16(*fullPort), uint16(*altFullPort)}}, nil

	default:
		return nil, fmt.Errorf("invalid command: %s (commands: simple, full)", os.Args[1])
	}
}
