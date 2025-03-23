package messages

import (
	"bytes"
	"fmt"

	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// ChannelOpenMessage represents the SSH_MSG_CHANNEL_OPEN message
type ChannelOpenMessage struct {
	BaseMessage
	ChannelType   string
	SenderChannel uint32
	InitialWindow uint32
	MaxPacketSize uint32
	ChannelData   []byte
}

// NewChannelOpenMessage creates a new ChannelOpen message
func NewChannelOpenMessage(channelType string, senderChannel, initialWindow, maxPacketSize uint32, channelData []byte) *ChannelOpenMessage {
	return &ChannelOpenMessage{
		BaseMessage:   BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_OPEN},
		ChannelType:   channelType,
		SenderChannel: senderChannel,
		InitialWindow: initialWindow,
		MaxPacketSize: maxPacketSize,
		ChannelData:   channelData,
	}
}

// Marshal serializes the ChannelOpen message
func (m *ChannelOpenMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write channel type
	WriteString(&buf, m.ChannelType)

	// Write sender channel
	WriteUint32(&buf, m.SenderChannel)

	// Write initial window size
	WriteUint32(&buf, m.InitialWindow)

	// Write max packet size
	WriteUint32(&buf, m.MaxPacketSize)

	// Write channel specific data if any
	if len(m.ChannelData) > 0 {
		buf.Write(m.ChannelData)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelOpen message
func (m *ChannelOpenMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read channel type
	m.ChannelType, offset, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	// Read sender channel
	m.SenderChannel, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read initial window size
	m.InitialWindow, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read max packet size
	m.MaxPacketSize, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read remaining data as channel specific data
	if offset < len(data) {
		m.ChannelData = data[offset:]
	} else {
		m.ChannelData = []byte{}
	}

	return nil
}

// ChannelOpenConfirmMessage represents the SSH_MSG_CHANNEL_OPEN_CONFIRM message
type ChannelOpenConfirmMessage struct {
	BaseMessage
	RecipientChannel uint32
	SenderChannel    uint32
	InitialWindow    uint32
	MaxPacketSize    uint32
	ChannelData      []byte
}

// NewChannelOpenConfirmMessage creates a new ChannelOpenConfirm message
func NewChannelOpenConfirmMessage(recipientChannel, senderChannel, initialWindow, maxPacketSize uint32, channelData []byte) *ChannelOpenConfirmMessage {
	return &ChannelOpenConfirmMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_OPEN_CONFIRM},
		RecipientChannel: recipientChannel,
		SenderChannel:    senderChannel,
		InitialWindow:    initialWindow,
		MaxPacketSize:    maxPacketSize,
		ChannelData:      channelData,
	}
}

// Marshal serializes the ChannelOpenConfirm message
func (m *ChannelOpenConfirmMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	// Write sender channel
	WriteUint32(&buf, m.SenderChannel)

	// Write initial window size
	WriteUint32(&buf, m.InitialWindow)

	// Write max packet size
	WriteUint32(&buf, m.MaxPacketSize)

	// Write channel specific data if any
	if len(m.ChannelData) > 0 {
		buf.Write(m.ChannelData)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelOpenConfirm message
func (m *ChannelOpenConfirmMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read recipient channel
	m.RecipientChannel, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read sender channel
	m.SenderChannel, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read initial window size
	m.InitialWindow, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read max packet size
	m.MaxPacketSize, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read remaining data as channel specific data
	if offset < len(data) {
		m.ChannelData = data[offset:]
	} else {
		m.ChannelData = []byte{}
	}

	return nil
}

// ChannelOpenFailureMessage represents the SSH_MSG_CHANNEL_OPEN_FAILURE message
type ChannelOpenFailureMessage struct {
	BaseMessage
	RecipientChannel uint32
	ReasonCode       uint32
	Description      string
	Language         string
}

// NewChannelOpenFailureMessage creates a new ChannelOpenFailure message
func NewChannelOpenFailureMessage(recipientChannel, reasonCode uint32, description, language string) *ChannelOpenFailureMessage {
	return &ChannelOpenFailureMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_OPEN_FAILURE},
		RecipientChannel: recipientChannel,
		ReasonCode:       reasonCode,
		Description:      description,
		Language:         language,
	}
}

// Marshal serializes the ChannelOpenFailure message
func (m *ChannelOpenFailureMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	// Write reason code
	WriteUint32(&buf, m.ReasonCode)

	// Write description
	WriteString(&buf, m.Description)

	// Write language tag
	WriteString(&buf, m.Language)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelOpenFailure message
func (m *ChannelOpenFailureMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read recipient channel
	m.RecipientChannel, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read reason code
	m.ReasonCode, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read description
	m.Description, offset, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	// Read language tag
	m.Language, _, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// ChannelWindowAdjustMessage represents the SSH_MSG_CHANNEL_WINDOW_ADJUST message
type ChannelWindowAdjustMessage struct {
	BaseMessage
	RecipientChannel uint32
	BytesToAdd       uint32
}

// NewChannelWindowAdjustMessage creates a new ChannelWindowAdjust message
func NewChannelWindowAdjustMessage(recipientChannel, bytesToAdd uint32) *ChannelWindowAdjustMessage {
	return &ChannelWindowAdjustMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_WINDOW_ADJUST},
		RecipientChannel: recipientChannel,
		BytesToAdd:       bytesToAdd,
	}
}

// Marshal serializes the ChannelWindowAdjust message
func (m *ChannelWindowAdjustMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	// Write bytes to add
	WriteUint32(&buf, m.BytesToAdd)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelWindowAdjust message
func (m *ChannelWindowAdjustMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read recipient channel
	m.RecipientChannel, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read bytes to add
	m.BytesToAdd, _, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// ChannelDataMessage represents the SSH_MSG_CHANNEL_DATA message
type ChannelDataMessage struct {
	BaseMessage
	RecipientChannel uint32
	Data             []byte
}

// NewChannelDataMessage creates a new ChannelData message
func NewChannelDataMessage(recipientChannel uint32, data []byte) *ChannelDataMessage {
	return &ChannelDataMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_DATA},
		RecipientChannel: recipientChannel,
		Data:             data,
	}
}

// Marshal serializes the ChannelData message
func (m *ChannelDataMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	// Write data
	WriteBytes(&buf, m.Data)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelData message
func (m *ChannelDataMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read recipient channel
	m.RecipientChannel, offset, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	// Read data
	m.Data, _, err = ReadBytes(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// ChannelEOFMessage represents the SSH_MSG_CHANNEL_EOF message
type ChannelEOFMessage struct {
	BaseMessage
	RecipientChannel uint32
}

// NewChannelEOFMessage creates a new ChannelEOF message
func NewChannelEOFMessage(recipientChannel uint32) *ChannelEOFMessage {
	return &ChannelEOFMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_EOF},
		RecipientChannel: recipientChannel,
	}
}

// Marshal serializes the ChannelEOF message
func (m *ChannelEOFMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelEOF message
func (m *ChannelEOFMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read recipient channel
	m.RecipientChannel, _, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// ChannelCloseMessage represents the SSH_MSG_CHANNEL_CLOSE message
type ChannelCloseMessage struct {
	BaseMessage
	RecipientChannel uint32
}

// NewChannelCloseMessage creates a new ChannelClose message
func NewChannelCloseMessage(recipientChannel uint32) *ChannelCloseMessage {
	return &ChannelCloseMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_CLOSE},
		RecipientChannel: recipientChannel,
	}
}

// Marshal serializes the ChannelClose message
func (m *ChannelCloseMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelClose message
func (m *ChannelCloseMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read recipient channel
	m.RecipientChannel, _, err = ReadUint32(data, offset)
	if err != nil {
		return err
	}

	return nil
}
