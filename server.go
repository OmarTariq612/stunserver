package stunserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
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

const (
	defaultTimeoutDuration = 3 * time.Second
	DefaultPort            = 3478
)

type agent struct {
	active    bool
	addrs     *[2]netip.Addr
	ports     *[2]uint16
	addrIndex int
	portIndex int

	udpConn net.PacketConn

	server *server
}

func (a *agent) index() int {
	return (a.portIndex << 1) | a.addrIndex
}

func (a agent) String() string {
	return fmt.Sprintf("{active=%v, ip=%s, port=%d, otherip=%s, otherport=%d}", a.active, a.addrs[a.addrIndex], a.ports[a.portIndex], a.otherAddr(), a.otherPort())
}

func (a *agent) primaryAddr() netip.AddrPort {
	return netip.MustParseAddrPort(a.addrs[a.addrIndex].String() + ":" + strconv.Itoa(int((*a.ports)[a.portIndex])))
}
func (a *agent) otherAddr() netip.Addr { return (*a.addrs)[(a.addrIndex+1)%2] }
func (a *agent) otherPort() uint16     { return (*a.ports)[(a.portIndex+1)%2] }
func (a *agent) otherAddrPort() netip.AddrPort {
	return netip.MustParseAddrPort(a.otherAddr().String() + ":" + strconv.Itoa(int(a.otherPort())))
}

func (a *agent) ListenAndServe() error {
	chErr := make(chan error)
	go func() { chErr <- a.ListenAndServeTCP() }()
	go func() { chErr <- a.ListenAndServeUDP() }()
	return <-chErr
}

func (a *agent) ListenAndServeTCP() error {
	l, err := net.Listen("tcp", a.primaryAddr().String())
	if err != nil {
		// logError(err.Error())
		return err
	}
	defer l.Close()

	logInfo("[TCP] Listening on: %s", l.Addr())

	for {
		conn, err := l.Accept()
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("[TCP] received: %s [from %s]", conn.RemoteAddr(), a.primaryAddr())
		go a.handleTCPRequest(conn)
	}
}

func (a *agent) ListenAndServeUDP() error {
	udpListener, err := net.ListenPacket("udp", a.primaryAddr().String())
	if err != nil {
		// logError(err.Error())
		return err
	}
	defer udpListener.Close()

	logInfo("[UDP] Listening on: %s", udpListener.LocalAddr().String())
	a.udpConn = udpListener

	buf := make([]byte, MaxMessageSize)
	for {
		n, addr, err := udpListener.ReadFrom(buf)
		if err != nil {
			logError(err.Error())
			continue
		}
		logInfo("[UDP] received: %s [from %s]", addr, a.primaryAddr())
		a.handleUDPRequest(udpListener, addr, buf[:n])
	}
}

var bufs = sync.Pool{
	New: func() any {
		bytesBuf := new(bytes.Buffer)
		bytesBuf.Grow(MaxMessageSize)
		return bytesBuf
	},
}

func (a *agent) handleTCPRequest(conn net.Conn) {
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
		if err = conn.SetReadDeadline(time.Now().Add(a.server.readTimeoutDuration)); err != nil {
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

		if err = conn.SetReadDeadline(time.Now().Add(a.server.readTimeoutDuration)); err != nil {
			logError(err.Error())
			return
		}

		_, err = io.ReadFull(conn, buf[MessageHeaderSize:MessageHeaderSize+length])
		if err != nil {
			logError(err.Error())
			return
		}

		buf = buf[:MessageHeaderSize+length]

		if err = conn.SetWriteDeadline(time.Now().Add(a.server.writeTimeoutDuration)); err != nil {
			logError(err.Error())
			return
		}

		if err = a.ProcessAndRespond(conn, buf, addrPort); err != nil {
			logError(err.Error())
		}
	}
}

func (a *agent) handleUDPRequest(conn net.PacketConn, srcAddr net.Addr, buf []byte) {
	addrPort, err := netip.ParseAddrPort(srcAddr.String())
	if err != nil {
		logError(err.Error())
		return
	}

	if err := a.ProcessAndRespond(BindPacketConn(conn, srcAddr), buf, addrPort); err != nil {
		logError(err.Error())
	}
}

func (a *agent) ProcessAndRespond(conn net.Conn, buf []byte, addr netip.AddrPort) error {
	var reqMessage Message
	if err := Decode(buf, &reqMessage); err != nil {
		return err
	}

	switch reqMessage.Type {
	case BindingRequest:
		respMessage, err := Build(&reqMessage, BindingSuccess)
		if err != nil {
			return err
		}

		var mappedAddress MappedAddress
		mappedAddress.IP, mappedAddress.Port = netipAddrToNetAddr(addr)
		if err = mappedAddress.AddTo(respMessage); err != nil {
			return err
		}

		var xorMappedAddress XORMappedAddress
		xorMappedAddress.IP, xorMappedAddress.Port = netipAddrToNetAddr(addr)
		if err = xorMappedAddress.AddTo(respMessage); err != nil {
			return err
		}

		if a.server.sendOtherAddressAttr {
			var otherAddress OtherAddress
			otherAddress.IP, otherAddress.Port = netipAddrToNetAddr(a.otherAddrPort())
			if err = otherAddress.AddTo(respMessage); err != nil {
				return err
			}

			var changeRequest ChangeRequest
			if err = changeRequest.GetFrom(&reqMessage); err == nil {
				switch {
				case changeRequest.ChangeIPAndPort():
					conn = BindPacketConn(a.server.agents[a.index()^0b11].udpConn, conn.RemoteAddr())
				case changeRequest.ChangeIP():
					conn = BindPacketConn(a.server.agents[a.index()^0b01].udpConn, conn.RemoteAddr())
				case changeRequest.ChangePort():
					conn = BindPacketConn(a.server.agents[a.index()^0b10].udpConn, conn.RemoteAddr())
				}
			}
		}

		if a.server.sendResponseOriginAttr {
			originAddr, err := netip.ParseAddrPort(conn.LocalAddr().String())
			if err != nil {
				return err
			}

			var responseOrigin ResponseOrigin
			responseOrigin.IP, responseOrigin.Port = netipAddrToNetAddr(originAddr)
			if err = responseOrigin.AddTo(respMessage); err != nil {
				return err
			}
		}

		if a.server.softwareAttr != "" {
			respMessage.Add(AttrSoftware, []byte(a.server.softwareAttr))
		}

		_, err = conn.Write(respMessage.Raw)
		return err
	}

	return nil
}

type agents [4]agent

func (as *agents) configureSimpleMode(addr netip.AddrPort, server *server) {
	addrs := [2]netip.Addr{addr.Addr()}
	ports := [2]uint16{addr.Port()}

	as[0].active = true
	as[0].addrs = &addrs
	as[0].ports = &ports
	as[0].addrIndex = 0
	as[0].portIndex = 0
	as[0].server = server
}

func (as *agents) configureFullMode(A1, A2 netip.Addr, P1, P2 uint16, server *server) {
	addrs := [2]netip.Addr{A1, A2}
	ports := [2]uint16{P1, P2}
	// 0      1      2        3
	// A1(0)  A2(1)  A1(0)    A2(1)   addrs
	// P1(0)  P1(0)  P2(1)    P2(1)   ports
	for i := range as {
		as[i].active = true
		as[i].addrs = &addrs
		as[i].ports = &ports
		as[i].addrIndex = i & 1
		as[i].portIndex = (i >> 1) & 1
		as[i].server = server
	}
}

func (as *agents) ListenAndServe() error {
	// var wg sync.WaitGroup
	chErr := make(chan error)
	for i := range as {
		if as[i].active {
			go func(i int) { chErr <- as[i].ListenAndServe() }(i)
		}
	}
	return <-chErr
}

type server struct {
	agents agents

	sendResponseOriginAttr bool
	sendOtherAddressAttr   bool
	softwareAttr           string

	readTimeoutDuration  time.Duration
	writeTimeoutDuration time.Duration
}

type ServerOption func(*server)

func NewServer(opts ...ServerOption) *server {
	s := &server{
		sendResponseOriginAttr: false,
		sendOtherAddressAttr:   false,
		softwareAttr:           "",
		readTimeoutDuration:    defaultTimeoutDuration,
		writeTimeoutDuration:   defaultTimeoutDuration,
	}
	s.agents.configureSimpleMode(netip.MustParseAddrPort(fmt.Sprintf("0.0.0.0:%d", DefaultPort)), s)

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func WithSimpleMode(addr netip.AddrPort) ServerOption {
	return func(s *server) {
		s.agents.configureSimpleMode(addr, s)
	}
}

func WithFullMode(A1, A2 netip.Addr, P1, P2 uint16) ServerOption {
	return func(s *server) {
		s.sendResponseOriginAttr = true
		s.sendOtherAddressAttr = true
		s.agents.configureFullMode(A1, A2, P1, P2, s)
	}
}

func WithSoftwareAttr(software string) ServerOption {
	return func(s *server) {
		s.softwareAttr = software
	}
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
	return s.agents.ListenAndServe()
}
