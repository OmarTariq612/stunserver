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

type server struct {
	udpListener net.PacketConn
	tcpListener net.Listener

	addr               string
	sendResponseOrigin bool

	readTimeoutDuration  time.Duration
	writeTimeoutDuration time.Duration
}

const defaultTimeoutDuration = 3 * time.Second

type ServerOption func(*server)

func NewServer(addr string, opts ...ServerOption) (*server, error) {
	s := &server{
		addr:                 addr,
		sendResponseOrigin:   true,
		readTimeoutDuration:  defaultTimeoutDuration,
		writeTimeoutDuration: defaultTimeoutDuration,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func WithoutResponseOrigin(s *server) {
	s.sendResponseOrigin = false
}

func WithReadTimeoutDuration(d time.Duration) ServerOption {
	return func(s *server) {
		s.readTimeoutDuration = d
	}
}

func WithWriteTimeoutDuration(d time.Duration) ServerOption {
	return func(s *server) {
		s.writeTimeoutDuration = d
	}
}

func (s *server) ListenAndServe() error {
	logInfo("Listening on: %s", s.addr)
	var err error
	s.tcpListener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer s.tcpListener.Close()
	s.udpListener, err = net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	defer s.udpListener.Close()

	addrPort, _ := netip.ParseAddrPort(s.tcpListener.Addr().String())
	if addrPort.Addr().IsUnspecified() {
		s.sendResponseOrigin = false
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go s.ListenAndServeTCP(&wg)
	go s.ListenAndServeUDP(&wg)
	wg.Wait()

	return nil
}

func (s *server) ListenAndServeUDP(wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, MaxMessageSize)

	for {
		n, addr, err := s.udpListener.ReadFrom(buf)
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("[UDP] received: %s", addr.String())
		s.handleUDPRequest(s.udpListener, addr, buf[:n])
	}
}

func (s *server) ListenAndServeTCP(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		tcpConn, err := s.tcpListener.Accept()
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("[TCP] received: %s", tcpConn.RemoteAddr().String())
		go s.handleTCPRequest(tcpConn)
	}
}

func (s *server) handleUDPRequest(conn net.PacketConn, srcAddr net.Addr, buf []byte) {
	addrPort, err := netip.ParseAddrPort(srcAddr.String())
	if err != nil {
		logError(err.Error())
		return
	}

	if err := s.ProcessAndRespond(BindPacketConn(conn, srcAddr), buf, addrPort); err != nil {
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

func (s *server) handleTCPRequest(conn net.Conn) {
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
		if err = conn.SetReadDeadline(time.Now().Add(s.readTimeoutDuration)); err != nil {
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

		if err = conn.SetReadDeadline(time.Now().Add(s.readTimeoutDuration)); err != nil {
			logError(err.Error())
			return
		}

		_, err = io.ReadFull(conn, buf[MessageHeaderSize:MessageHeaderSize+length])
		if err != nil {
			logError(err.Error())
			return
		}

		buf = buf[:MessageHeaderSize+length]

		if err = conn.SetWriteDeadline(time.Now().Add(s.writeTimeoutDuration)); err != nil {
			logError(err.Error())
			return
		}

		if err = s.ProcessAndRespond(conn, buf, addrPort); err != nil {
			logError(err.Error())
		}
	}
}

func (s *server) ProcessAndRespond(conn net.Conn, buf []byte, addr netip.AddrPort) error {
	var reqMessage Message
	if err := Decode(buf, &reqMessage); err != nil {
		return err
	}

	respMessage, err := Build(&reqMessage, BindingSuccess)
	if err != nil {
		return err
	}

	var srcAddr struct {
		ip   net.IP
		port uint16
	}
	ip := addr.Addr()
	if ip.Is4() {
		ipv4 := ip.As4()
		srcAddr.ip = ipv4[:]
	} else {
		ipv6 := ip.As16()
		srcAddr.ip = ipv6[:]
	}
	srcAddr.port = addr.Port()

	mappedAddr := MappedAddress{IP: srcAddr.ip, Port: int(srcAddr.port)}
	if err = mappedAddr.AddTo(respMessage); err != nil {
		return err
	}

	xorMappedAddress := XORMappedAddress{IP: srcAddr.ip, Port: int(srcAddr.port)}
	if err = xorMappedAddress.AddTo(respMessage); err != nil {
		return err
	}

	if s.sendResponseOrigin {
		originAddr, err := netip.ParseAddrPort(conn.LocalAddr().String())
		if err != nil {
			return err
		}

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
	}

	_, err = conn.Write(respMessage.Raw)
	return err
}
