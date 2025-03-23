package messages

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// KexDHInitMessage represents the SSH_MSG_KEXDH_INIT message
type KexDHInitMessage struct {
	BaseMessage
	E *big.Int // Client's public key
}

// NewKexDHInitMessage creates a new KexDHInit message
func NewKexDHInitMessage(e *big.Int) *KexDHInitMessage {
	return &KexDHInitMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_KEXDH_INIT},
		E:           e,
	}
}

// Marshal serializes the KexDHInit message
func (m *KexDHInitMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write e as mpint (multiple precision integer)
	WriteBytes(&buf, m.E.Bytes())

	return buf.Bytes(), nil
}

// Unmarshal deserializes the KexDHInit message
func (m *KexDHInitMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	// Read e as mpint
	eBytes, newOffset, err := ReadBytes(data, offset)
	if err != nil {
		return err
	}
	offset = newOffset

	m.E = new(big.Int).SetBytes(eBytes)

	return nil
}

// KexDHReplyMessage represents the SSH_MSG_KEXDH_REPLY message
type KexDHReplyMessage struct {
	BaseMessage
	HostKey   []byte   // Server's host key
	F         *big.Int // Server's public key
	Signature []byte   // Signature of the exchange hash
}

// NewKexDHReplyMessage creates a new KexDHReply message
func NewKexDHReplyMessage(hostKey []byte, f *big.Int, signature []byte) *KexDHReplyMessage {
	return &KexDHReplyMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_KEXDH_REPLY},
		HostKey:     hostKey,
		F:           f,
		Signature:   signature,
	}
}

// Marshal serializes the KexDHReply message
func (m *KexDHReplyMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write host key as string
	WriteBytes(&buf, m.HostKey)

	// Write f as mpint
	WriteBytes(&buf, m.F.Bytes())

	// Write signature as string
	WriteBytes(&buf, m.Signature)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the KexDHReply message
func (m *KexDHReplyMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read host key as string
	m.HostKey, offset, err = ReadBytes(data, offset)
	if err != nil {
		return err
	}

	// Read f as mpint
	fBytes, offset, err := ReadBytes(data, offset)
	if err != nil {
		return err
	}
	m.F = new(big.Int).SetBytes(fBytes)

	// Read signature as string
	m.Signature, _, err = ReadBytes(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// NewKeysMessage represents the SSH_MSG_NEWKEYS message
type NewKeysMessage struct {
	BaseMessage
}

// NewNewKeysMessage creates a new NewKeys message
func NewNewKeysMessage() *NewKeysMessage {
	return &NewKeysMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_NEWKEYS},
	}
}

// Marshal serializes the NewKeys message
func (m *NewKeysMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the NewKeys message
func (m *NewKeysMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	// Read message type
	m.MessageType = data[0]

	return nil
}
