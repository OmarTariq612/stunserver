package stunserver

import (
	"errors"
	"fmt"
	"io"
)

// ChangeRquest represents CHANGE-REQUEST attribute.
//
// RFC 5780 Section 7.2
type ChangeRequest struct {
	value byte
}

func (c ChangeRequest) ChangeIPAndPort() bool { return c.value == 6 }
func (c ChangeRequest) ChangeIP() bool        { return c.value == 4 }
func (c ChangeRequest) ChangePort() bool      { return c.value == 2 }
func (c ChangeRequest) String() string {
	return fmt.Sprintf("{changeip=%v, changeport=%v}", (c.value|4) == 1, (c.value|2) == 1)
}

var (
	ErrTypeIsNotBindingRequest  = errors.New("ChangeRequest can be only applied to BindingRequest messages")
	ErrInvalidChangeRequstValue = errors.New("Invalid ChangeRequest value")
)

func (c ChangeRequest) AddTo(m *Message) error {
	if m.Type != BindingRequest {
		return ErrTypeIsNotBindingRequest
	}
	value := make([]byte, 4)
	value[3] = c.value
	m.Add(AttrChangeRequest, value)
	return nil
}

func (c *ChangeRequest) GetFrom(m *Message) error {
	if m.Type != BindingRequest {
		return ErrTypeIsNotBindingRequest
	}
	v, err := m.Get(AttrChangeRequest)
	if err != nil {
		return err
	}
	if len(v) != 4 {
		return io.ErrUnexpectedEOF
	}
	value := v[3]
	if value != 2 && value != 4 && value != 6 {
		return ErrInvalidChangeRequstValue
	}
	c.value = value
	return nil
}
