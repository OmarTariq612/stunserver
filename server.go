package stunserver

import (
	"fmt"
	"log"
	"net"
	"net/netip"
)

func logInfo(msg string, args ...any) {
	log.Printf("[INFO]: %s", fmt.Sprintf(msg, args...))
}

func logError(msg string, args ...any) {
	log.Printf("[ERROR]: %s", fmt.Sprintf(msg, args...))
}

func logFatal(msg string, args ...any) {
	log.Fatalf("[FATAL]: %s", fmt.Sprintf(msg, args...))
}

func ListenAndServe(addr string) error {
	logInfo("Listening on: %s", addr)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}

	buf := make([]byte, 1280)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("received: %s", addr.String())
		if err = handleRequest(conn, addr, buf[:n]); err != nil {
			logError(err.Error())
		}
	}
}

func handleRequest(conn net.PacketConn, srcAddr net.Addr, buf []byte) error {
	addrPort, err := netip.ParseAddrPort(srcAddr.String())
	if err != nil {
		return err
	}

	var reqMessage Message
	if err = Decode(buf, &reqMessage); err != nil {
		return err
	}

	respMessage, err := Build(&reqMessage, BindingSuccess)
	if err != nil {
		return err
	}

	var xorMappedAddr XORMappedAddress
	ip := addrPort.Addr()
	if ip.Is4() {
		ipv4 := ip.As4()
		xorMappedAddr.IP = ipv4[:]
	} else {
		ipv6 := ip.As16()
		xorMappedAddr.IP = ipv6[:]
	}
	xorMappedAddr.Port = int(addrPort.Port())
	if err := xorMappedAddr.AddTo(respMessage); err != nil {
		return err
	}

	_, err = conn.WriteTo(respMessage.Raw, srcAddr)
	return err
}
