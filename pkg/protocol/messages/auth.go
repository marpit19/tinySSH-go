package messages

import (
	"bytes"
	"fmt"

	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// ServiceRequestMessage represents the SSH_MSG_SERVICE_REQUEST message
type ServiceRequestMessage struct {
	BaseMessage
	ServiceName string
}

// NewServiceRequestMessage creates a new ServiceRequest message
func NewServiceRequestMessage(serviceName string) *ServiceRequestMessage {
	return &ServiceRequestMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_SERVICE_REQUEST},
		ServiceName: serviceName,
	}
}

// Marshal serializes the ServiceRequest message
func (m *ServiceRequestMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write service name
	WriteString(&buf, m.ServiceName)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ServiceRequest message
func (m *ServiceRequestMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	// Read service name
	var err error
	m.ServiceName, _, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// ServiceAcceptMessage represents the SSH_MSG_SERVICE_ACCEPT message
type ServiceAcceptMessage struct {
	BaseMessage
	ServiceName string
}

// NewServiceAcceptMessage creates a new ServiceAccept message
func NewServiceAcceptMessage(serviceName string) *ServiceAcceptMessage {
	return &ServiceAcceptMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_SERVICE_ACCEPT},
		ServiceName: serviceName,
	}
}

// Marshal serializes the ServiceAccept message
func (m *ServiceAcceptMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write service name
	WriteString(&buf, m.ServiceName)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the ServiceAccept message
func (m *ServiceAcceptMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	// Read service name
	var err error
	m.ServiceName, _, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	return nil
}

// UserAuthRequestMessage represents the SSH_MSG_USERAUTH_REQUEST message
type UserAuthRequestMessage struct {
	BaseMessage
	Username    string
	ServiceName string
	MethodName  string
	MethodData  []byte
}

// NewUserAuthRequestMessage creates a new UserAuthRequest message
func NewUserAuthRequestMessage(username, serviceName, methodName string, methodData []byte) *UserAuthRequestMessage {
	return &UserAuthRequestMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_USERAUTH_REQUEST},
		Username:    username,
		ServiceName: serviceName,
		MethodName:  methodName,
		MethodData:  methodData,
	}
}

// Marshal serializes the UserAuthRequest message
func (m *UserAuthRequestMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write username
	WriteString(&buf, m.Username)

	// Write service name
	WriteString(&buf, m.ServiceName)

	// Write method name
	WriteString(&buf, m.MethodName)

	// Write method-specific data
	if len(m.MethodData) > 0 {
		buf.Write(m.MethodData)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes the UserAuthRequest message
func (m *UserAuthRequestMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read username
	m.Username, offset, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	// Read service name
	m.ServiceName, offset, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	// Read method name
	m.MethodName, offset, err = ReadString(data, offset)
	if err != nil {
		return err
	}

	// Read remaining data as method-specific data
	if offset < len(data) {
		m.MethodData = data[offset:]
	} else {
		m.MethodData = []byte{}
	}

	return nil
}

// UserAuthSuccessMessage represents the SSH_MSG_USERAUTH_SUCCESS message
type UserAuthSuccessMessage struct {
	BaseMessage
}

// NewUserAuthSuccessMessage creates a new UserAuthSuccess message
func NewUserAuthSuccessMessage() *UserAuthSuccessMessage {
	return &UserAuthSuccessMessage{
		BaseMessage: BaseMessage{MessageType: protocol.SSH_MSG_USERAUTH_SUCCESS},
	}
}

// Marshal serializes the UserAuthSuccess message
func (m *UserAuthSuccessMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	return buf.Bytes(), nil
}

// Unmarshal deserializes the UserAuthSuccess message
func (m *UserAuthSuccessMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	// Read message type
	m.MessageType = data[0]

	return nil
}

// UserAuthFailureMessage represents the SSH_MSG_USERAUTH_FAILURE message
type UserAuthFailureMessage struct {
	BaseMessage
	AuthMethodsRemaining []string
	PartialSuccess       bool
}

// NewUserAuthFailureMessage creates a new UserAuthFailure message
func NewUserAuthFailureMessage(methods []string, partialSuccess bool) *UserAuthFailureMessage {
	return &UserAuthFailureMessage{
		BaseMessage:          BaseMessage{MessageType: protocol.SSH_MSG_USERAUTH_FAILURE},
		AuthMethodsRemaining: methods,
		PartialSuccess:       partialSuccess,
	}
}

// Marshal serializes the UserAuthFailure message
func (m *UserAuthFailureMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write message type
	buf.WriteByte(m.MessageType)

	// Write auth methods as name-list
	WriteNameList(&buf, m.AuthMethodsRemaining)

	// Write partial success
	if m.PartialSuccess {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes the UserAuthFailure message
func (m *UserAuthFailureMessage) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too short for message type")
	}

	offset := 0

	// Read message type
	m.MessageType = data[offset]
	offset++

	var err error

	// Read auth methods name-list
	m.AuthMethodsRemaining, offset, err = ReadNameList(data, offset)
	if err != nil {
		return err
	}

	// Read partial success
	if offset >= len(data) {
		return fmt.Errorf("buffer too short for partial success")
	}
	m.PartialSuccess = data[offset] != 0

	return nil
}

// UserAuthPasswordRequestData contains the data for a password authentication request
type UserAuthPasswordRequestData struct {
	ChangePassword bool
	Password       string
	NewPassword    string // Only used if ChangePassword is true
}

// MarshalPasswordRequestData serializes password auth request data
func MarshalPasswordRequestData(password string) []byte {
	var buf bytes.Buffer

	// Write change password flag (false)
	buf.WriteByte(0)

	// Write password
	WriteString(&buf, password)

	return buf.Bytes()
}

// UnmarshalPasswordRequestData deserializes password auth request data
func UnmarshalPasswordRequestData(data []byte) (*UserAuthPasswordRequestData, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("buffer too short for change password flag")
	}

	offset := 0

	// Read change password flag
	changePassword := data[offset] != 0
	offset++

	var err error
	var password, newPassword string

	// Read password
	password, offset, err = ReadString(data, offset)
	if err != nil {
		return nil, err
	}

	// Read new password if changing
	if changePassword && offset < len(data) {
		newPassword, _, err = ReadString(data, offset)
		if err != nil {
			return nil, err
		}
	}

	return &UserAuthPasswordRequestData{
		ChangePassword: changePassword,
		Password:       password,
		NewPassword:    newPassword,
	}, nil
}
