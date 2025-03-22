package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// Message is the interface common functionality for SSH messages
type Message interface {
	Type() byte
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

// BaseMessage contains common functionality for SSH messages
type BaseMessage struct {
	MessageType byte
}

// Type returns the message type
func (m *BaseMessage) Type() byte {
	return m.MessageType
}

func MessageTypeString(msgType byte) string {
	switch msgType {
	case protocol.SSH_MSG_DISCONNECT:
		return "SSH_MSG_DISCONNECT"
	case protocol.SSH_MSG_IGNORE:
		return "SSH_MSG_IGNORE"
	case protocol.SSH_MSG_UNIMPLEMENTED:
		return "SSH_MSG_UNIMPLEMENTED"
	case protocol.SSH_MSG_DEBUG:
		return "SSH_MSG_DEBUG"
	case protocol.SSH_MSG_SERVICE_REQUEST:
		return "SSH_MSG_SERVICE_REQUEST"
	case protocol.SSH_MSG_SERVICE_ACCEPT:
		return "SSH_MSG_SERVICE_ACCEPT"
	case protocol.SSH_MSG_KEXINIT:
		return "SSH_MSG_KEXINIT"
	case protocol.SSH_MSG_NEWKEYS:
		return "SSH_MSG_NEWKEYS"
	case protocol.SSH_MSG_KEXDH_INIT:
		return "SSH_MSG_KEXDH_INIT"
	case protocol.SSH_MSG_KEXDH_REPLY:
		return "SSH_MSG_KEXDH_REPLY"
	case protocol.SSH_MSG_USERAUTH_REQUEST:
		return "SSH_MSG_USERAUTH_REQUEST"
	case protocol.SSH_MSG_USERAUTH_FAILURE:
		return "SSH_MSG_USERAUTH_FAILURE"
	case protocol.SSH_MSG_USERAUTH_SUCCESS:
		return "SSH_MSG_USERAUTH_SUCCESS"
	case protocol.SSH_MSG_USERAUTH_BANNER:
		return "SSH_MSG_USERAUTH_BANNER"
	case protocol.SSH_MSG_GLOBAL_REQUEST:
		return "SSH_MSG_GLOBAL_REQUEST"
	case protocol.SSH_MSG_REQUEST_SUCCESS:
		return "SSH_MSG_REQUEST_SUCCESS"
	case protocol.SSH_MSG_REQUEST_FAILURE:
		return "SSH_MSG_REQUEST_FAILURE"
	case protocol.SSH_MSG_CHANNEL_OPEN:
		return "SSH_MSG_CHANNEL_OPEN"
	case protocol.SSH_MSG_CHANNEL_OPEN_CONFIRM:
		return "SSH_MSG_CHANNEL_OPEN_CONFIRM"
	case protocol.SSH_MSG_CHANNEL_OPEN_FAILURE:
		return "SSH_MSG_CHANNEL_OPEN_FAILURE"
	case protocol.SSH_MSG_CHANNEL_WINDOW_ADJUST:
		return "SSH_MSG_CHANNEL_WINDOW_ADJUST"
	case protocol.SSH_MSG_CHANNEL_DATA:
		return "SSH_MSG_CHANNEL_DATA"
	case protocol.SSH_MSG_CHANNEL_EXTENDED_DATA:
		return "SSH_MSG_CHANNEL_EXTENDED_DATA"
	case protocol.SSH_MSG_CHANNEL_EOF:
		return "SSH_MSG_CHANNEL_EOF"
	case protocol.SSH_MSG_CHANNEL_CLOSE:
		return "SSH_MSG_CHANNEL_CLOSE"
	case protocol.SSH_MSG_CHANNEL_REQUEST:
		return "SSH_MSG_CHANNEL_REQUEST"
	case protocol.SSH_MSG_CHANNEL_SUCCESS:
		return "SSH_MSG_CHANNEL_SUCCESS"
	case protocol.SSH_MSG_CHANNEL_FAILURE:
		return "SSH_MSG_CHANNEL_FAILURE"
	default:
		return fmt.Sprintf("UNKNOWN_MESSAGE_TYPE(%d)", msgType)
	}
}

// Utility functions for encoding/decoding messages

// WriteUint32 writes a uint32 in big endian format
/*
Example:
buf := &bytes.Buffer{}
WriteUint32(buf, 42)
fmt.Println(buf.Bytes()) // Output: [0 0 0 42]

Why use Big-Endian? => Big-endian is used because it's the network standard.
42 in big-endian 4 bytes is: 0x00 0x00 0x00 0x2A.
*/
func WriteUint32(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	buf.Write(b)
}

// WriteString writes a string as length-prefixed byte array
/*
Example:
buf := &bytes.Buffer{}
WriteString(buf, "hello")
fmt.Println(buf.Bytes())
// Output: [0 0 0 5 104 101 108 108 111]

Why?
0 0 0 5 → The string length (5 bytes).
104 101 108 108 111 → ASCII values of "hello".
*/
func WriteString(buf *bytes.Buffer, s string) {
	WriteUint32(buf, uint32(len(s)))
	buf.WriteString(s)
}

// WriteBytes writes a byte slice as a length-prefixed array
// WriteBytes(buf, []byte{1, 2, 3})
// 0 0 0 3 -> length of byte slice (3 bytes), 1 2 3 -> actual data
// Output: [0 0 0 3 1 2 3]
func WriteBytes(buf *bytes.Buffer, b []byte) {
	WriteUint32(buf, uint32(len(b)))
	buf.Write(b)
}

// ReadUint32 reads a uint32 in big endian format
// data := []byte{0, 0, 0, 42} || value, newOffset, err := ReadUint32(data, 0)
// 0 0 0 42 → Big-endian encoding for 42
// Output: 42 4
func ReadUint32(data []byte, offset int) (uint32, int, error) {
	if offset+4 > len(data) {
		return 0, offset, fmt.Errorf("buffer too short for uint32")
	}
	v := binary.BigEndian.Uint32(data[offset:])
	return v, offset + 4, nil
}

// ReadString reads a length prefixed string
// data := []byte{0, 0, 0, 5, 104, 101, 108, 108, 111} // "hello"
// str, newOffset, err := ReadString(data, 0)
// Output: hello 9
func ReadString(data []byte, offset int) (string, int, error) {
	length, newOffset, err := ReadUint32(data, offset)
	if err != nil {
		return "", offset, err
	}

	if newOffset+int(length) > len(data) {
		return "", offset, fmt.Errorf("buffer too short for string")
	}

	s := string(data[newOffset : newOffset+int(length)])
	return s, newOffset + int(length), nil
}

// ReadBytes reads a length-prefixed byte array
/*
data := []byte{0, 0, 0, 3, 10, 20, 30} 
b, newOffset, err := ReadBytes(data, 0)
fmt.Println(b, newOffset) // Output: [10 20 30] 7

Why?
0 0 0 3 → Byte slice length (3 bytes).
10 20 30 → Actual byte slice data.
*/
func ReadBytes(data []byte, offset int) ([]byte, int, error) {
	length, newOffset, err := ReadUint32(data, offset)
	if err != nil {
		return nil, offset, err
	}

	if newOffset+int(length) > len(data) {
		return nil, offset, fmt.Errorf("buffer too short for byte array")
	}

	b := data[newOffset : newOffset+int(length)]
	return b, newOffset + int(length), nil
}
