package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/crypto"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// Packet represents an SSH binary packet
type Packet struct {
	Type    byte
	Payload []byte
}

// PacketConn wraps a network connection to implement the binary packet protocol
type PacketConn struct {
	Conn           net.Conn
	logger         *logging.Logger
	SequenceNumber uint32
	lastActivity   time.Time
	Session        *crypto.Session
	hostKey        *crypto.HostKey
	isEncrypted    bool
}

// NewPacketConn creates a new SSH packet connection
func NewPacketConn(conn net.Conn, logger *logging.Logger, hostKey *crypto.HostKey) (*PacketConn, error) {
	// initialize session
	session, err := crypto.NewSession()
	if err != nil {
		return nil, err
	}

	return &PacketConn{
		Conn:           conn,
		logger:         logger,
		SequenceNumber: 0,
		lastActivity:   time.Now(),
		Session:         session,
		hostKey:        hostKey,
		isEncrypted:    false,
	}, nil
}

// key exchange methods

// InitiateKeyExchange starts the key exchange process
func (pc *PacketConn) InitiateKeyExchange(clientKexInit, serverKexInit []byte) error {
	// Store key exchange messages for session ID calculation
	pc.Session.ClientKeyExchange = clientKexInit
	pc.Session.ServerKeyExchange = serverKexInit

	return nil
}

// HandleDHInit processes the client's SSH_MSG_KEXDH_INIT message
func (pc *PacketConn) HandleDHInit(clientPublicKey *big.Int) (*big.Int, []byte, error) {
	// Get server's public key
	serverPublicKey := pc.Session.DH.PublicKey

	// Calculate shared secret
	sharedSecret := pc.Session.DH.ComputeSharedSecret(clientPublicKey)

	// Store keys for session ID calculation
	clientPublicKeyBytes := clientPublicKey.Bytes()
	serverPublicKeyBytes := serverPublicKey.Bytes()

	// Generate session ID
	sessionID := crypto.GenerateSessionID(
		pc.Session.ClientKeyExchange,
		pc.Session.ServerKeyExchange,
		clientPublicKeyBytes,
		serverPublicKeyBytes,
		sharedSecret.Bytes(),
	)

	pc.Session.ID = sessionID

	// Generate session keys
	keys := crypto.DeriveKeys(sharedSecret.Bytes(), sessionID)
	pc.Session.SetKeys(keys)

	// Generate signature of the exchange hash
	signature, err := pc.hostKey.SignHash(sessionID)
	if err != nil {
		return nil, nil, err
	}

	return serverPublicKey, signature, nil
}

// EnableEncryption enables encryption for the connection
func (pc *PacketConn) EnableEncryption() {
	pc.isEncrypted = true
	pc.logger.Info("Encryption enabled for connection")
}

// ReadPacket reads a binary packet from the connection
// simplified implementation without encryption as of now (might do it later)
func (pc *PacketConn) ReadPacket() (*Packet, error) {
	// read packet length (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(pc.Conn, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read packet length: %v", err)
	}

	// decode packet length
	packetLen := binary.BigEndian.Uint32(lenBuf)

	// sanity check on packet length to avoid memory exhaustion attacks
	if packetLen > protocol.MaxPacketSize {
		return nil, fmt.Errorf("packet too large: %d > %d", packetLen, protocol.MaxPacketSize)
	}

	// read padding length (1 byte)
	padLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(pc.Conn, padLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read padding length: %v", err)
	}

	padLen := padLenBuf[0]

	// calculate payload length (packet length - padding length - 1)
	// the -1 is for the padding length byte itself
	payloadLen := int(packetLen) - int(padLen) - 1

	if payloadLen < 0 {
		return nil, fmt.Errorf("invalid packet: padding too large for packet length")
	}

	// read payload and padding
	data := make([]byte, payloadLen+int(padLen))
	if _, err := io.ReadFull(pc.Conn, data); err != nil {
		return nil, fmt.Errorf("failed to read packet data: %v", err)
	}

	// extract payload (ignore padding)
	payload := data[:payloadLen]

	// update last activity timestamp
	pc.lastActivity = time.Now()

	// increment sequence number
	pc.SequenceNumber++

	// create packet (first byte is message type)
	var packet Packet
	if len(payload) > 0 {
		packet.Type = payload[0]
		packet.Payload = payload[1:] // skip the message type byte
	}

	pc.logger.Debug("Read packet type: %d, length: %d", packet.Type, len(payload))

	return &packet, nil
}

// WritePacket writes a binary packet to the connection
// simplified implementation without encryption (as, might do it later)
func (pc *PacketConn) WritePacket(packet *Packet) error {
	// create a buffer for the packet
	var buf bytes.Buffer

	// write message type
	buf.WriteByte(packet.Type)

	// write payload
	buf.Write(packet.Payload)

	payload := buf.Bytes()
	payloadLen := len(payload)

	// calculate padding length (must be at least 4 bytes)
	// padding length should make the total a multiple of 8
	// packet format: uint32 packet_length, byte padding_length, payload, padding
	blockSize := 8
	paddingLen := blockSize - ((payloadLen + 5) % blockSize)
	if paddingLen < 4 {
		paddingLen += blockSize
	}

	// create padding
	padding := make([]byte, paddingLen)

	// calculate total packet length (excluding the 4 bytes for length itself)
	packetLen := 1 + payloadLen + paddingLen // 1 is for padding length byte

	// create header buffer
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[0:4], uint32(packetLen))
	header[4] = byte(paddingLen)

	// write the packet
	if _, err := pc.Conn.Write(header); err != nil {
		return fmt.Errorf("failed to write packet header: %v", err)
	}

	if _, err := pc.Conn.Write(payload); err != nil {
		return fmt.Errorf("failed to write packet payload: %v", err)
	}

	if _, err := pc.Conn.Write(padding); err != nil {
		return fmt.Errorf("failed to write packet padding: %v", err)
	}

	// update last activity timestamp
	pc.lastActivity = time.Now()

	// increment sequence number
	pc.SequenceNumber++

	pc.logger.Debug("Wrote packet type: %d, length: %d", packet.Type, payloadLen)

	return nil
}

// sendKeepAlive sends an SSH_MSG_IGNORE packet to keep the connection alive
func (pc *PacketConn) SendKeepAlive() error {
	// create an SSH_MSG_IGNORE packet with empty payload
	packet := &Packet{
		Type:    protocol.SSH_MSG_IGNORE,
		Payload: []byte{}, // empty payload
	}

	pc.logger.Debug("Sending keep-alive packet")
	return pc.WritePacket(packet)
}

// ShouldSendKeepAlive checks if it's time to send a keep-alive packet
func (pc *PacketConn) ShouldSendKeepAlive() bool {
	return time.Since(pc.lastActivity) > time.Duration(protocol.KeepAliveInterval)*time.Second
}

// StartKeepAlive starts a goroutine to periodically send keep-alive messages
func (pc *PacketConn) StartKeepAlive() {
	go func() {
		ticker := time.NewTicker(time.Duration(protocol.KeepAliveInterval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if pc.ShouldSendKeepAlive() {
				if err := pc.SendKeepAlive(); err != nil {
					pc.logger.Error("Failed to send keep-alive: %v", err)
					return
				}
			}
		}
	}()
}
