package stunserver

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var bin = binary.BigEndian

const (
	// MagicCookie is fixed value that aids in distinguishing STUN packets
	// from packets of other protocols when STUN is multiplexed with those
	// other protocols on the same Port.
	//
	// The magic cookie field MUST contain the fixed value 0x2112A442 in
	// network byte order.
	//
	// Defined in "STUN Message Structure", section 6.
	MagicCookie         = 0x2112A442
	AttributeHeaderSize = 4
	MessageHeaderSize   = 20
	MaxMessageSize      = 1280

	// TransactionIDSize is length of transaction id array (in bytes).
	TransactionIDSize = 12 // 96 bit
)

// Method is uint16 representation of 12-bit STUN method.
type Method uint16

// Possible methods for STUN Message.
const (
	MethodBinding          Method = 0x001
	MethodAllocate         Method = 0x003
	MethodRefresh          Method = 0x004
	MethodSend             Method = 0x006
	MethodData             Method = 0x007
	MethodCreatePermission Method = 0x008
	MethodChannelBind      Method = 0x009
)

// Methods from RFC 6062.
const (
	MethodConnect           Method = 0x000a
	MethodConnectionBind    Method = 0x000b
	MethodConnectionAttempt Method = 0x000c
)

func methodName() map[Method]string {
	return map[Method]string{
		MethodBinding:          "Binding",
		MethodAllocate:         "Allocate",
		MethodRefresh:          "Refresh",
		MethodSend:             "Send",
		MethodData:             "Data",
		MethodCreatePermission: "CreatePermission",
		MethodChannelBind:      "ChannelBind",

		// RFC 6062.
		MethodConnect:           "Connect",
		MethodConnectionBind:    "ConnectionBind",
		MethodConnectionAttempt: "ConnectionAttempt",
	}
}

func (m Method) String() string {
	s, ok := methodName()[m]
	if !ok {
		// Falling back to hex representation.
		s = fmt.Sprintf("0x%x", uint16(m))
	}
	return s
}

// MessageClass is 8-bit representation of 2-bit class of STUN Message Class.
type MessageClass byte

// Possible values for message class in STUN Message Type.
const (
	ClassRequest         MessageClass = 0x00 // 0b00
	ClassIndication      MessageClass = 0x01 // 0b01
	ClassSuccessResponse MessageClass = 0x02 // 0b10
	ClassErrorResponse   MessageClass = 0x03 // 0b11
)

func (c MessageClass) String() string {
	switch c {
	case ClassRequest:
		return "request"
	case ClassIndication:
		return "indication"
	case ClassSuccessResponse:
		return "success response"
	case ClassErrorResponse:
		return "error response"
	default:
		panic("unknown message class")
	}
}

// MessageType is STUN Message Type Field.
type MessageType struct {
	Method Method       // e.g. binding
	Class  MessageClass // e.g. request
}

func NewType(method Method, class MessageClass) MessageType {
	return MessageType{
		Method: method,
		Class:  class,
	}
}

// Common STUN message types.
var (
	// Binding request message type.
	BindingRequest = NewType(MethodBinding, ClassRequest) //nolint:gochecknoglobals
	// Binding success response message type
	BindingSuccess = NewType(MethodBinding, ClassSuccessResponse) //nolint:gochecknoglobals
	// Binding error response message type.
	BindingError = NewType(MethodBinding, ClassErrorResponse) //nolint:gochecknoglobals
)

// AddTo sets m type to t.
func (t MessageType) AddTo(m *Message) error {
	m.SetType(t)
	return nil
}

const (
	methodABits = 0xf   // 0b0000000000001111
	methodBBits = 0x70  // 0b0000000001110000
	methodDBits = 0xf80 // 0b0000111110000000

	methodBShift = 1
	methodDShift = 2

	firstBit  = 0x1
	secondBit = 0x2

	c0Bit = firstBit
	c1Bit = secondBit

	classC0Shift = 4
	classC1Shift = 7
)

func (t MessageType) Value() uint16 {
	//	 0                 1
	//	 2  3  4 5 6 7 8 9 0 1 2 3 4 5
	//	+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	//	|M |M |M|M|M|C|M|M|M|C|M|M|M|M|
	//	|11|10|9|8|7|1|6|5|4|0|3|2|1|0|
	//	+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	// Figure 3: Format of STUN Message Type Field

	// Warning: Abandon all hope ye who enter here.
	// Splitting M into A(M0-M3), B(M4-M6), D(M7-M11).
	m := uint16(t.Method)
	a := m & methodABits // A = M * 0b0000000000001111 (right 4 bits)
	b := m & methodBBits // B = M * 0b0000000001110000 (3 bits after A)
	d := m & methodDBits // D = M * 0b0000111110000000 (5 bits after B)

	// Shifting to add "holes" for C0 (at 4 bit) and C1 (8 bit).
	m = a + (b << methodBShift) + (d << methodDShift)

	// C0 is zero bit of C, C1 is first bit.
	// C0 = C * 0b01, C1 = (C * 0b10) >> 1
	// Ct = C0 << 4 + C1 << 8.
	// Optimizations: "((C * 0b10) >> 1) << 8" as "(C * 0b10) << 7"
	// We need C0 shifted by 4, and C1 by 8 to fit "11" and "7" positions
	// (see figure 3).
	c := uint16(t.Class)
	c0 := (c & c0Bit) << classC0Shift
	c1 := (c & c1Bit) << classC1Shift
	class := c0 + c1

	return m + class
}

// ReadValue decodes uint16 into MessageType.
func (t *MessageType) ReadValue(v uint16) {
	// Decoding class.
	// We are taking first bit from v >> 4 and second from v >> 7.
	c0 := (v >> classC0Shift) & c0Bit
	c1 := (v >> classC1Shift) & c1Bit
	class := c0 + c1
	t.Class = MessageClass(class)

	// Decoding method.
	a := v & methodABits                   // A(M0-M3)
	b := (v >> methodBShift) & methodBBits // B(M4-M6)
	d := (v >> methodDShift) & methodDBits // D(M7-M11)
	m := a + b + d
	t.Method = Method(m)
}

// NewTransactionID returns new random transaction ID using crypto/rand
// as source.
func NewTransactionID() (b [TransactionIDSize]byte) {
	readFullOrPanic(rand.Reader, b[:])
	return b
}

// Message represents a single STUN packet. It uses aggressive internal
// buffering to enable zero-allocation encoding and decoding,
// so there are some usage constraints:
//
//	Message, its fields, results of m.Get or any attribute a.GetFrom
//	are valid only until Message.Raw is not modified.
type Message struct {
	Type          MessageType
	Length        uint32 // len(Raw) not including header
	TransactionID [TransactionIDSize]byte
	Attributes    Attributes
	Raw           []byte
}

func (m Message) MarshalBinary() ([]byte, error) {
	return bytes.Clone(m.Raw), nil
}

func (m *Message) String() string {
	tID := base64.StdEncoding.EncodeToString(m.TransactionID[:])
	aInfo := ""
	for k, a := range m.Attributes {
		aInfo += fmt.Sprintf("attr%d=%s ", k, a.Type)
	}
	return fmt.Sprintf("%s l=%d attrs=%d id=%s, %s", m.Type, m.Length, len(m.Attributes), tID, aInfo)
}

// Reset resets Message, attributes and underlying buffer length.
func (m *Message) Reset() {
	m.Raw = m.Raw[:0]
	m.Length = 0
	m.Attributes = m.Attributes[:0]
}

// SetType sets m.Type and writes it to m.Raw.
func (m *Message) SetType(t MessageType) {
	m.Type = t
	m.WriteType()
}

// grow ensures that internal buffer has n length.
func (m *Message) grow(n int) {
	if len(m.Raw) >= n {
		return
	}
	if cap(m.Raw) >= n {
		m.Raw = m.Raw[:n]
		return
	}
	m.Raw = append(m.Raw, make([]byte, n-len(m.Raw))...)
}

// NewTransactionID sets m.TransactionID to random value from crypto/rand
// and returns error if any.
func (m *Message) NewTransactionID() error {
	_, err := io.ReadFull(rand.Reader, m.TransactionID[:])
	if err == nil {
		m.WriteTransactionID()
	}
	return err
}

// WriteType writes m.Type to m.Raw.
func (m *Message) WriteType() {
	m.grow(2)
	bin.PutUint16(m.Raw[0:2], m.Type.Value()) // message type
}

// WriteLength writes m.Length to m.Raw.
func (m *Message) WriteLength() {
	m.grow(4)
	bin.PutUint16(m.Raw[2:4], uint16(m.Length))
}

func (m *Message) WriteTransactionID() {
	// m.grow(20)
	copy(m.Raw[8:MessageHeaderSize], m.TransactionID[:])
}

// WriteHeader writes header to underlying buffer. Not goroutine-safe.
func (m *Message) WriteHeader() {
	m.grow(MessageHeaderSize)
	_ = m.Raw[:MessageHeaderSize] // early bounds check to guarantee safety of writes below

	m.WriteType()
	m.WriteLength()
	bin.PutUint32(m.Raw[4:8], MagicCookie)               // magic cookie
	copy(m.Raw[8:MessageHeaderSize], m.TransactionID[:]) // transaction ID
}

// WriteTransactionID writes m.TransactionID to m.Raw.

// Add appends new attribute to message. Not goroutine-safe.
//
// Value of attribute is copied to internal buffer so
// it is safe to reuse v.
func (m *Message) Add(t AttrType, v []byte) {
	// Allocating buffer for TLV (type-length-value).
	// T = t, L = len(v), V = v.
	// m.Raw will look like:
	// [0:20]                               <- message header
	// [20:20+m.Length]                     <- existing message attributes
	// [20+m.Length:20+m.Length+len(v) + 4] <- allocated buffer for new TLV
	// [first:last]                         <- same as previous
	// [0 1|2 3|4    4 + len(v)]            <- mapping for allocated buffer
	//   T   L        V
	allocSize := AttributeHeaderSize + len(v)  // ~ len(TLV) = len(TL) + len(V)
	first := MessageHeaderSize + int(m.Length) // first byte number
	last := first + allocSize                  // last byte number
	m.grow(last)                               // growing cap(Raw) to fit TLV
	m.Raw = m.Raw[:last]                       // now len(Raw) = last
	m.Length += uint32(allocSize)              // rendering length change

	// Sub-slicing internal buffer to simplify encoding.
	buf := m.Raw[first:last]           // slice for TLV
	value := buf[AttributeHeaderSize:] // slice for V
	attr := RawAttribute{
		Type:   t,              // T
		Length: uint16(len(v)), // L
		Value:  value,          // V
	}

	// Encoding attribute TLV to allocated buffer.
	bin.PutUint16(buf[0:2], attr.Type.Value()) // T
	bin.PutUint16(buf[2:4], attr.Length)       // L
	copy(value, v)                             // V

	// Checking that attribute value needs padding.
	if attr.Length%padding != 0 {
		// Performing padding.
		bytesToAdd := nearestPaddedValueLength(len(v)) - len(v)
		last += bytesToAdd
		m.grow(last)
		// setting all padding bytes to zero
		// to prevent data leak from previous
		// data in next bytesToAdd bytes
		buf = m.Raw[last-bytesToAdd : last]
		for i := range buf {
			buf[i] = 0
		}
		m.Raw = m.Raw[:last]           // increasing buffer length
		m.Length += uint32(bytesToAdd) // rendering length change
	}
	m.Attributes = append(m.Attributes, attr)
	m.WriteLength()
}

// WriteAttributes encodes all m.Attributes to m.
func (m *Message) WriteAttributes() {
	attributes := m.Attributes
	m.Attributes = m.Attributes[:0]
	for _, attr := range attributes {
		m.Add(attr.Type, attr.Value)
	}
	m.Attributes = attributes
}

// ErrUnexpectedHeaderEOF means that there were not enough bytes in
// m.Raw to read header.
var ErrUnexpectedHeaderEOF = errors.New("unexpected EOF: not enough bytes to read header")

// Decode decodes m.Raw into m.
func (m *Message) Decode() error {
	// decoding message header
	buf := m.Raw
	if len(buf) < MessageHeaderSize {
		return ErrUnexpectedHeaderEOF
	}
	var (
		t        = bin.Uint16(buf[0:2])      // first 2 bytes
		size     = int(bin.Uint16(buf[2:4])) // second 2 bytes
		cookie   = bin.Uint32(buf[4:8])      // last 4 bytes
		fullSize = MessageHeaderSize + size  // len(m.Raw)
	)
	if cookie != MagicCookie {
		msg := fmt.Sprintf("%x is invalid magic cookie (should be %x)", cookie, MagicCookie)
		return newDecodeErr("message", "cookie", msg)
	}
	if len(buf) < fullSize {
		msg := fmt.Sprintf("buffer length %d is less than %d (expected message size)", len(buf), fullSize)
		return newAttrDecodeErr("message", msg)
	}
	// saving header data
	m.Type.ReadValue(t)
	m.Length = uint32(size)
	copy(m.TransactionID[:], buf[8:MessageHeaderSize])

	m.Attributes = m.Attributes[:0]
	var (
		offset = 0
		b      = buf[MessageHeaderSize:fullSize]
	)
	for offset < size {
		// checking that we have enough bytes to read header
		if len(b) < AttributeHeaderSize {
			msg := fmt.Sprintf("buffer length %d is less than %d (expected header size)", len(b), AttributeHeaderSize)
			return newAttrDecodeErr("header", msg)
		}
		var (
			a = RawAttribute{
				Type:   compatAttrType(bin.Uint16(b[0:2])), // first 2 bytes
				Length: bin.Uint16(b[2:4]),                 // second 2 bytes
			}
			aL     = int(a.Length)                // attribute length
			aBuffL = nearestPaddedValueLength(aL) // expected buffer length (with padding)
		)
		b = b[AttributeHeaderSize:] // slicing again to simplify value read
		offset += AttributeHeaderSize
		if len(b) < aBuffL { // checking size
			msg := fmt.Sprintf("buffer length %d is less than %d (expected value size for %s)", len(b), aBuffL, a.Type)
			return newAttrDecodeErr("value", msg)
		}
		a.Value = b[:aL]
		offset += aBuffL
		b = b[aBuffL:]

		m.Attributes = append(m.Attributes, a)
	}
	return nil
}

// AddTo sets b.TransactionID to m.TransactionID.
//
// Implements Setter to aid in crafting responses.
func (src *Message) AddTo(dst *Message) error {
	dst.TransactionID = src.TransactionID
	dst.WriteTransactionID()
	return nil
}

// ErrDecodeToNil occurs on Decode(data, nil) call.
var ErrDecodeToNil = errors.New("attempt to decode to nil message")

// Decode decodes Message from data to m, returning error if any.
func Decode(data []byte, m *Message) error {
	if m == nil {
		return ErrDecodeToNil
	}
	m.Raw = append(m.Raw[:0], data...)
	return m.Decode()
}

// IsMessage returns true if b looks like STUN message.
// Useful for multiplexing. IsMessage does not guarantee
// that decoding will be successful.
func IsMessage(b []byte) bool {
	return len(b) >= MessageHeaderSize && bin.Uint32(b[4:8]) == MagicCookie
}
