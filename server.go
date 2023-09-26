package stunserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
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
	buf := make([]byte, MaxMessageSize)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("[UDP] received: %s", addr.String())
		handleUDPRequest(conn, addr, buf[:n])
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
		logInfo("[TCP] received: %s", tcpConn.RemoteAddr().String())
		go handleTCPRequest(tcpConn)
	}
}

func handleUDPRequest(conn net.PacketConn, srcAddr net.Addr, buf []byte) {
	addrPort, err := netip.ParseAddrPort(srcAddr.String())
	if err != nil {
		logError(err.Error())
		return
	}

	if err := ProcessAndRespond(BindPacketConn(conn, srcAddr), buf, addrPort); err != nil {
		logError(err.Error())
	}
}

var bufs = sync.Pool{
	New: func() any {
		bytesBuf := new(bytes.Buffer)
		bytesBuf.Grow(MaxMessageSize)
		return bytesBuf
	},
}

func handleTCPRequest(conn net.Conn) {
	defer conn.Close()

	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		logError(err.Error())
		return
	}

	bytesBuf := bufs.Get().(*bytes.Buffer)
	bytesBuf.Reset()
	defer bufs.Put(bytesBuf)

	buf := bytesBuf.AvailableBuffer()
	buf = buf[:MaxMessageSize]

	for {
		if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			logError(err.Error())
			return
		}

		_, err = io.ReadFull(conn, buf[:MessageHeaderSize])
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logError(err.Error())
			}
			return
		}

		length := bin.Uint16(buf[2:4])

		if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			logError(err.Error())
			return
		}

		_, err = io.ReadFull(conn, buf[MessageHeaderSize:MessageHeaderSize+length])
		if err != nil {
			logError(err.Error())
			return
		}

		buf = buf[:MessageHeaderSize+length]

		if err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			logError(err.Error())
			return
		}

		if err = ProcessAndRespond(conn, buf, addrPort); err != nil {
			logError(err.Error())
		}
	}
}

func ProcessAndRespond(conn net.Conn, buf []byte, addr netip.AddrPort) error {
	var reqMessage Message
	if err := Decode(buf, &reqMessage); err != nil {
		return err
	}

	respMessage, err := Build(&reqMessage, BindingSuccess)
	if err != nil {
		return err
	}

	var xorMappedAddr XORMappedAddress
	ip := addr.Addr()
	if ip.Is4() {
		ipv4 := ip.As4()
		xorMappedAddr.IP = ipv4[:]
	} else {
		ipv6 := ip.As16()
		xorMappedAddr.IP = ipv6[:]
	}
	xorMappedAddr.Port = int(addr.Port())
	if err = xorMappedAddr.AddTo(respMessage); err != nil {
		return err
	}

	originAddr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}

	// FIXME: origin address is ipv6 even though the client sent request over ipv4
	var responseOrigin ResponseOrigin
	localIP := originAddr.Addr()
	if localIP.Is4() {
		ipv4 := localIP.As4()
		responseOrigin.IP = ipv4[:]
	} else {
		ipv6 := localIP.As16()
		responseOrigin.IP = ipv6[:]
	}
	responseOrigin.Port = int(originAddr.Port())

	if err = responseOrigin.AddTo(respMessage); err != nil {
		return err
	}

	_, err = conn.Write(respMessage.Raw)
	return err
}
