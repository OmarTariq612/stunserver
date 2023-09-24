package stunserver

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