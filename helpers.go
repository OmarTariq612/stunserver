package stunserver

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

// Interfaces that are implemented by message attributes, shorthands for them,
// or helpers for message fields as type or transaction id.
type (
	// Setter sets *Message attribute.
	Setter interface {
		AddTo(m *Message) error
	}
	// Getter parses attribute from *Message.
	Getter interface {
		GetFrom(m *Message) error
	}
	// Checker checks *Message attribute.
	Checker interface {
		Check(m *Message) error
	}
)

// Build resets message and applies setters to it in batch, returning on
// first error. To prevent allocations, pass pointers to values.
//
// Example:
//
//	var (
//		t        = BindingRequest
//		username = NewUsername("username")
//		nonce    = NewNonce("nonce")
//		realm    = NewRealm("example.org")
//	)
//	m := new(Message)
//	m.Build(t, username, nonce, realm)     // 4 allocations
//	m.Build(&t, &username, &nonce, &realm) // 0 allocations
//
// See BenchmarkBuildOverhead.
func (m *Message) Build(setters ...Setter) error {
	m.Reset()
	m.WriteHeader()
	for _, s := range setters {
		if err := s.AddTo(m); err != nil {
			return err
		}
	}
	return nil
}

// Check applies checkers to message in batch, returning on first error.
func (m *Message) Check(checkers ...Checker) error {
	for _, c := range checkers {
		if err := c.Check(m); err != nil {
			return err
		}
	}
	return nil
}

// Parse applies getters to message in batch, returning on first error.
func (m *Message) Parse(getters ...Getter) error {
	for _, c := range getters {
		if err := c.GetFrom(m); err != nil {
			return err
		}
	}
	return nil
}

// MustBuild wraps Build call and panics on error.
func MustBuild(setters ...Setter) *Message {
	m, err := Build(setters...)
	if err != nil {
		panic(err) //nolint
	}
	return m
}

// Build wraps Message.Build method.
func Build(setters ...Setter) (*Message, error) {
	m := new(Message)
	if err := m.Build(setters...); err != nil {
		return nil, err
	}
	return m, nil
}

func XOR(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

type wrappedPacketConn struct {
	net.PacketConn
	addr net.Addr
}

func (conn *wrappedPacketConn) Read(b []byte) (n int, err error) {
	for {
		var addr net.Addr
		n, addr, err = conn.ReadFrom(b)
		if addr.Network() != conn.addr.Network() || addr.String() != conn.addr.String() {
			continue
		}
		break
	}
	return n, err
}

func (conn *wrappedPacketConn) Write(b []byte) (n int, err error) {
	n, err = conn.WriteTo(b, conn.addr)
	return n, err
}

func (conn *wrappedPacketConn) RemoteAddr() net.Addr {
	return conn.addr
}

func BindPacketConn(conn net.PacketConn, addr net.Addr) net.Conn {
	return &wrappedPacketConn{PacketConn: conn, addr: addr}
}

func netipAddrToNetAddr(addr netip.AddrPort) (net.IP, int) {
	return net.IP(addr.Addr().AsSlice()), int(addr.Port())
}

func isUp(i *net.Interface) bool       { return i.Flags&net.FlagUp != 0 }
func isLoopback(i *net.Interface) bool { return i.Flags&net.FlagLoopback != 0 }

type Interface struct {
	*net.Interface
}

func (i Interface) IsUp() bool       { return isUp(i.Interface) }
func (i Interface) IsLoopback() bool { return isLoopback(i.Interface) }

type Interfaces []Interface

func GetInterfaces() (Interfaces, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	nifs := make([]Interface, len(interfaces))
	for i := range interfaces {
		nifs[i].Interface = &interfaces[i]
	}

	return nifs, nil
}

func WalkInterfacesAddrs(f func(Interface, netip.Addr) error) error {
	nifs, err := GetInterfaces()
	if err != nil {
		return err
	}
	return nifs.WalkInterfacesAddrs(f)
}

var ErrStopWalking = errors.New("stop walking")

func (nifs Interfaces) WalkInterfacesAddrs(f func(Interface, netip.Addr) error) error {
	for _, nif := range nifs {
		addrs, err := nif.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			addrStr := addr.String()
			if !strings.Contains(addrStr, "/") {
				continue
			}
			if err = f(nif, netip.MustParseAddr(strings.Split(addrStr, "/")[0])); err != nil {
				return err
			}
		}
	}
	return nil
}
