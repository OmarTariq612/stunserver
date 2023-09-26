package stunserver

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
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
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer tcpListener.Close()
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go ListenAndServeTCP(tcpListener, &wg)
	go ListenAndServeUDP(udpConn, &wg)
	wg.Wait()

	return nil
}

func ListenAndServeUDP(conn net.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1280)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("received: %s", addr.String())
		if err = handleUDPRequest(conn, addr, buf[:n]); err != nil {
			logError(err.Error())
		}
	}
}

func ListenAndServeTCP(l net.Listener, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		tcpConn, err := l.Accept()
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("received: %s", tcpConn.RemoteAddr().String())
		go handleTCPRequest(tcpConn)
	}
}

func handleUDPRequest(conn net.PacketConn, srcAddr net.Addr, buf []byte) error {
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

var bufs = sync.Pool{
	New: func() any {
		bytesBuf := new(bytes.Buffer)
		bytesBuf.Grow(1280)
		return bytesBuf
	},
}

func handleTCPRequest(conn net.Conn) {
	defer func() {
		conn.Close()
		logInfo("closing connection [%s]", conn.RemoteAddr())
	}()

	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		logError(err.Error())
		return
	}

	bytesBuf := bufs.Get().(*bytes.Buffer)
	bytesBuf.Reset()
	defer bufs.Put(bytesBuf)

	buf := bytesBuf.AvailableBuffer()
	buf = buf[:1280]
	log.Println(len(buf))

	for {
		_, err = io.ReadFull(conn, buf[:MessageHeaderSize])
		if err != nil {
			logError(err.Error())
			return
		}

		length := bin.Uint16(buf[2:4])

		_, err = io.ReadFull(conn, buf[MessageHeaderSize:MessageHeaderSize+length])
		if err != nil {
			logError(err.Error())
			return
		}

		buf = buf[:MessageHeaderSize+length]

		var reqMessage Message
		if err = Decode(buf, &reqMessage); err != nil {
			logError(err.Error())
			return
		}

		respMessage, err := Build(&reqMessage, BindingSuccess)
		if err != nil {
			logError(err.Error())
			return
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
			logError(err.Error())
		}

		_, err = conn.Write(respMessage.Raw)
		if err != nil {
			logError(err.Error())
		}
	}
}
