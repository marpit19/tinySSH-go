package messages

import (
	"bytes"
	"fmt"

	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// ChannelRequestMessage represents the SSH_MSG_CHANNEL_REQUEST message
type ChannelRequestMessage struct {
	BaseMessage
	RecipientChannel uint32
	RequestType      string
	WantReply        bool
	RequestData      []byte
}

// NewChannelRequestMessage creates a new ChannelRequest message
func NewChannelRequestMessage(recipientChannel uint32, requestType string, wantReply bool, requestData []byte) *ChannelRequestMessage {
	return &ChannelRequestMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_REQUEST},
		RecipientChannel: recipientChannel,
		RequestType:      requestType,
		WantReply:        wantReply,
		RequestData:      requestData,
	}
}

// Marshal serializes the ChannelRequest message
func (m *ChannelRequestMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	// Write request type
	WriteString(&buf, m.RequestType)

	// Write want reply
	if m.WantReply {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	// Write request-specific data
	if len(m.RequestData) > 0 {
		buf.Write(m.RequestData)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelRequest message
func (m *ChannelRequestMessage) Unmarshal(data []byte) error {
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

	// Read request type
	m.RequestType, offset, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	// Read want reply
	if offset >= len(data) {
		return fmt.Errorf("buffer too short for want reply")
	}
	m.WantReply = data[offset] != 0
	offset++

	// Read remaining data as request-specific data
	if offset < len(data) {
		m.RequestData = data[offset:]
	} else {
		m.RequestData = []byte{}
	}

	return nil
}

// ChannelSuccessMessage represents the SSH_MSG_CHANNEL_SUCCESS message
type ChannelSuccessMessage struct {
	BaseMessage
	RecipientChannel uint32
}

// NewChannelSuccessMessage creates a new ChannelSuccess message
func NewChannelSuccessMessage(recipientChannel uint32) *ChannelSuccessMessage {
	return &ChannelSuccessMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_SUCCESS},
		RecipientChannel: recipientChannel,
	}
}

// Marshal serializes the ChannelSuccess message
func (m *ChannelSuccessMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelSuccess message
func (m *ChannelSuccessMessage) Unmarshal(data []byte) error {
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

// ChannelFailureMessage represents the SSH_MSG_CHANNEL_FAILURE message
type ChannelFailureMessage struct {
	BaseMessage
	RecipientChannel uint32
}

// NewChannelFailureMessage creates a new ChannelFailure message
func NewChannelFailureMessage(recipientChannel uint32) *ChannelFailureMessage {
	return &ChannelFailureMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_FAILURE},
		RecipientChannel: recipientChannel,
	}
}

// Marshal serializes the ChannelFailure message
func (m *ChannelFailureMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelFailure message
func (m *ChannelFailureMessage) Unmarshal(data []byte) error {
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

// ChannelExtendedDataMessage represents the SSH_MSG_CHANNEL_EXTENDED_DATA message
type ChannelExtendedDataMessage struct {
	BaseMessage
	RecipientChannel uint32
	DataTypeCode     uint32
	Data             []byte
}

// ExtendedDataTypes
const (
	ExtendedDataStderr uint32 = 1
)

// NewChannelExtendedDataMessage creates a new ChannelExtendedData message
func NewChannelExtendedDataMessage(recipientChannel, dataTypeCode uint32, data []byte) *ChannelExtendedDataMessage {
	return &ChannelExtendedDataMessage{
		BaseMessage:      BaseMessage{MessageType: protocol.SSH_MSG_CHANNEL_EXTENDED_DATA},
		RecipientChannel: recipientChannel,
		DataTypeCode:     dataTypeCode,
		Data:             data,
	}
}

// Marshal serializes the ChannelExtendedData message
func (m *ChannelExtendedDataMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write recipient channel
	WriteUint32(&buf, m.RecipientChannel)

	// Write data type code
	WriteUint32(&buf, m.DataTypeCode)

	// Write data
	WriteBytes(&buf, m.Data)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ChannelExtendedData message
func (m *ChannelExtendedDataMessage) Unmarshal(data []byte) error {
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

	// Read data type code
	m.DataTypeCode, offset, err = ReadUint32(data, offset)
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

// ExecRequestData contains the data for an exec request
type ExecRequestData struct {
	Command string
}

// MarshalExecRequestData serializes exec request data
func MarshalExecRequestData(command string) []byte {
	var buf bytes.Buffer

	// Write command
	WriteString(&buf, command)

	return buf.Bytes()
}

// UnmarshalExecRequestData deserializes exec request data
func UnmarshalExecRequestData(data []byte) (*ExecRequestData, error) {
	if len(data) < 4 { // At least 4 bytes for command length
		return nil, fmt.Errorf("buffer too short for exec request data")
	}

	command, _, err := ReadString(data, 0)
	if err != nil {
		return nil, err
	}

	return &ExecRequestData{
		Command: command,
	}, nil
}

// ExitStatusMessage contains the data for an exit-status request
type ExitStatusMessage struct {
	ExitStatus uint32
}

// MarshalExitStatusMessage serializes exit status message
func MarshalExitStatusMessage(exitStatus uint32) []byte {
	var buf bytes.Buffer

	// Write exit status
	WriteUint32(&buf, exitStatus)

	return buf.Bytes()
}

// UnmarshalExitStatusMessage deserializes exit status message
func UnmarshalExitStatusMessage(data []byte) (*ExitStatusMessage, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("buffer too short for exit status message")
	}

	exitStatus, _, err := ReadUint32(data, 0)
	if err != nil {
		return nil, err
	}

	return &ExitStatusMessage{
		ExitStatus: exitStatus,
	}, nil
}
