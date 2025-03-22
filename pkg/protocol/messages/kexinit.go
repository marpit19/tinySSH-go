package messages

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// KexInitMessage represents the SSH_MSG_KEXINIT message
type KexInitMessage struct {
	BaseMessage
	Cookie                     [16]byte
	KexAlgorithms              []string
	ServerHostKeyAlgorithms    []string
	EncryptionAlgorithmsClient []string
	EncryptionAlgorithmsServer []string
	MacAlgorithmsClient        []string
	MacAlgorithmsServer        []string
	CompressionAlgorithmsClient []string
	CompressionAlgorithmsServer []string
	LanguagesClient            []string
	LanguagesServer            []string
	FirstKexPacketFollows      bool
	Reserved                   uint32
}

// NewKexInitMessage creates a new KexInit message with default algorithms
func NewKexInitMessage() *KexInitMessage {
	msg := &KexInitMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_KEXINIT},
		// Simplified algorithm lists for educational purposes
		KexAlgorithms:              []string{"diffie-hellman-group14-sha1"},
		ServerHostKeyAlgorithms:    []string{"ssh-rsa"},
		EncryptionAlgorithmsClient: []string{"aes128-ctr"},
		EncryptionAlgorithmsServer: []string{"aes128-ctr"},
		MacAlgorithmsClient:        []string{"hmac-sha1"},
		MacAlgorithmsServer:        []string{"hmac-sha1"},
		CompressionAlgorithmsClient: []string{"none"},
		CompressionAlgorithmsServer: []string{"none"},
		LanguagesClient:            []string{},
		LanguagesServer:            []string{},
		FirstKexPacketFollows:      false,
		Reserved:                   0,
	}

	// Generate random cookie
	rand.Read(msg.Cookie[:])

	return msg
}

// Marshal serializes the KexInit message
func (m *KexInitMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write cookie
	buf.Write(m.Cookie[:])

	// Write name-lists
	WriteNameList(&buf, m.KexAlgorithms)
	WriteNameList(&buf, m.ServerHostKeyAlgorithms)
	WriteNameList(&buf, m.EncryptionAlgorithmsClient)
	WriteNameList(&buf, m.EncryptionAlgorithmsServer)
	WriteNameList(&buf, m.MacAlgorithmsClient)
	WriteNameList(&buf, m.MacAlgorithmsServer)
	WriteNameList(&buf, m.CompressionAlgorithmsClient)
	WriteNameList(&buf, m.CompressionAlgorithmsServer)
	WriteNameList(&buf, m.LanguagesClient)
	WriteNameList(&buf, m.LanguagesServer)

	// Write boolean
	if m.FirstKexPacketFollows {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	// Write reserved
	WriteUint32(&buf, m.Reserved)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the KexInit message
func (m *KexInitMessage) Unmarshal(data []byte) error {
	if len(data) < 17 { // Type byte + 16-byte cookie
		return ErrShortBuffer
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	// Read cookie
	copy(m.Cookie[:], data[offset:offset+16])
	offset += 16

	var err error

	// Read name-lists
	m.KexAlgorithms, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.ServerHostKeyAlgorithms, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.EncryptionAlgorithmsClient, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.EncryptionAlgorithmsServer, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.MacAlgorithmsClient, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.MacAlgorithmsServer, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.CompressionAlgorithmsClient, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.CompressionAlgorithmsServer, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.LanguagesClient, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	m.LanguagesServer, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	// Read first_kex_packet_follows
	if offset >= len(data) {
		return ErrShortBuffer
	}
	m.FirstKexPacketFollows = data[offset] != 0
	offset++

	// Read reserved
	if offset+4 > len(data) {
		return ErrShortBuffer
	}
	m.Reserved = binary.BigEndian.Uint32(data[offset:])

	return nil
}

// Helper functions for name lists

// WriteNameList writes a comma-separated list of names
func WriteNameList(buf *bytes.Buffer, list []string) {
	nameList := bytes.Join([][]byte{}, []byte{','})
	for i, name := range list {
		if i > 0 {
			nameList = append(nameList, ',')
		}
		nameList = append(nameList, []byte(name)...)
	}
	WriteUint32(buf, uint32(len(nameList)))
	buf.Write(nameList)
}

// ReadNameList reads a comma-separated list of names
func ReadNameList(data []byte, offset int) ([]string, int, error) {
	length, newOffset, err := ReadUint32(data, offset)
	if err != nil {
		return nil, offset, err
	}

	if newOffset+int(length) > len(data) {
		return nil, offset, ErrShortBuffer
	}

	nameListBytes := data[newOffset : newOffset+int(length)]
	var names []string

	if length > 0 {
		namesBytes := bytes.Split(nameListBytes, []byte{','})
		for _, name := range namesBytes {
			names = append(names, string(name))
		}
	}

	return names, newOffset + int(length), nil
}

// Error types
var (
	ErrShortBuffer = fmt.Errorf("buffer too short")
)
