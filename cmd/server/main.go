package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/crypto"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
	"github.com/marpit19/tinySSH-go/pkg/protocol/messages"
	"github.com/marpit19/tinySSH-go/pkg/protocol/transport"
)

var (
	hostKey     *crypto.HostKey
	connections = make(map[string]*transport.PacketConn)
	connMutex   sync.Mutex
	shutdown    = make(chan struct{})
)

func main() {
	// Parse cli flags
	port := flag.Int("port", 2222, "Port to listen on")
	host := flag.String("host", "localhost", "Host to listen on")
	keyPath := flag.String("key", "ssh_host_key", "Path to host key file")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// Initalize logger
	logger := logging.NewLogger("server")
	logger.Info("Starting TinySSH-Go server on %s", addr)

	// Load or generate host key
	var err error
	hostKey, err = crypto.LoadOrGenerateHostKey(*keyPath)
	if err != nil {
		logger.Error("Failed to load or generate host key: %v", err)
		os.Exit(1)
	}
	logger.Info("Host key loaded/generated syccessfully")

	// Create TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Failed to start listener: %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("Server is listening for connections")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a channel to signal accepted connections
	connChan := make(chan net.Conn)

	// Accept connections in a goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the listener was closed intentionally
				select {
				case <-shutdown:
					return
				default:
					if opErr, ok := err.(*net.OpError); ok {
						if opErr.Err.Error() == "use of closed network connection" {
							return
						}
					}
					logger.Error("Error accepting connection: %v", err)
					continue
				}
			}
			connChan <- conn
		}
	}()

	// start a goroutine to handle console commands
	go handleConsoleCommands(logger, listener)

	// Main server loop
	for {
		select {
		case conn := <-connChan:
			// Handle each connection in a new goroutine
			go handleConnection(conn, logger)
		case sig := <-sigChan:
			logger.Info("Received signal: %v, shutting down", sig)
			shutdownServer(logger, listener)
			return
		case <-shutdown:
			logger.Info("Shutdown command received, shutting down")
			shutdownServer(logger, listener)
			return
		}
	}
}

// handle console commands
func handleConsoleCommands(logger *logging.Logger, listener net.Listener) {
	scanner := bufio.NewScanner(os.Stdin)
	logger.Info("Server commands interface ready. Type 'exit()' to shutdown.")

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		switch command {
		case "exit()":
			logger.Info("Exit command received. Shutting down server...")
			close(shutdown)
			return
		case "status":
			connMutex.Lock()
			logger.Info("Active connections: %d", len(connections))
			for addr := range connections {
				logger.Info("  - %s", addr)
			}
			connMutex.Unlock()
		case "help":
			logger.Info("Available commands:")
			logger.Info("  exit()  - Shutdown the server")
			logger.Info("  status  - Show active connections")
			logger.Info("  help    - Show this help message")
		default:
			if command != "" {
				logger.Info("Unknown command: %s (type 'help' for available commands)", command)
			}
		}
	}
}

// shutdownServer will do graceful shutdown
func shutdownServer(logger *logging.Logger, listener net.Listener) {
	logger.Info("Closing all connections...")

	// Close all active connections
	connMutex.Lock()
	for addr, conn := range connections {
		logger.Info("Closing connection to %s", addr)
		conn.Conn.Close()
		delete(connections, addr)
	}
	connMutex.Unlock()

	// Close listener
	logger.Info("Closing listener...")
	listener.Close()

	logger.Info("Server shutdown complete")
}

// handleConnection processes a new client connection
func handleConnection(conn net.Conn, logger *logging.Logger) {
	remoteAddr := conn.RemoteAddr().String()
	logger.Info("New connection from %s", remoteAddr)

	// register handleConnection
	connMutex.Lock()
	packetConn, err := transport.NewPacketConn(conn, logger, hostKey)
	if err != nil {
		logger.Error("failed to create packet connection: %v", err)
		conn.Close()
		connMutex.Unlock()
		return
	}
	connections[remoteAddr] = packetConn
	connMutex.Unlock()

	defer func() {
		conn.Close()

		// Unregister connection
		connMutex.Lock()
		delete(connections, remoteAddr)
		connMutex.Unlock()

		logger.Info("Connection from %s closed", remoteAddr)
	}()

	// Perform SSH version exchange
	remoteVersion, err := transport.ExchangeVersions(conn, logger, true)
	if err != nil {
		logger.Error("Version exchange failed with %s: %v", remoteAddr, err)
		return
	}

	logger.Info("Client %s version: %s", remoteAddr, remoteVersion)

	// Create and marshal our key exchange init message
	kexInitMsg := messages.NewKexInitMessage()
	serverKexInitBytes, err := kexInitMsg.Marshal()
	if err != nil {
		logger.Error("Failed to marshal KEXINIT: %v", err)
		return
	}

	// Send our key exchange init message
	err = packetConn.WritePacket(&transport.Packet{
		Type:    protocol.SSH_MSG_KEXINIT,
		Payload: serverKexInitBytes[1:], // skip the message type byte
	})
	if err != nil {
		logger.Error("Failed to send KEXINIT: %v", err)
		return
	}

	// variables to track key exchange state
	var clientKexInitBytes []byte
	var keyExchangeComplete bool

	for {
		select {
		case <-shutdown:
			logger.Info("Server is shutting down, closing connection to %s", remoteAddr)
			return
		default:
			// Continue normal processing
		}

		packet, err := packetConn.ReadPacket()
		if err != nil {
			if err.Error() == "EOF" {
				logger.Info("Client %s disconnected", remoteAddr)
			} else {
				logger.Error("Error reading packet from %s: %v", remoteAddr, err)
			}
			return
		}

		logger.Info("Received message type: %s", messages.MessageTypeString(packet.Type))

		// Handle different message types
		switch packet.Type {
		case protocol.SSH_MSG_KEXINIT:
			logger.Info("Received KEXINIT from client")
			clientKexInitBytes = append([]byte{packet.Type}, packet.Payload...)

			// Initialize key exchange
			err = packetConn.InitiateKeyExchange(clientKexInitBytes, serverKexInitBytes)
			if err != nil {
				logger.Error("Failed to initiate key exchange: %v", err)
				return
			}

		case protocol.SSH_MSG_KEXDH_INIT:
			logger.Info("Received KEXDH_INIT from client")

			// Parse client's public key
			kexDHInit := &messages.KexDHInitMessage{}
			err := kexDHInit.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal KEXDH_INIT: %v", err)
				return
			}

			// Process DH init and generate our response
			serverPublicKey, signature, err := packetConn.HandleDHInit(kexDHInit.E)
			if err != nil {
				logger.Error("Failed to handle KEXDH_INIT: %v", err)
				return
			}

			// Create and send DH reply
			kexDHReply := messages.NewKexDHReplyMessage(
				hostKey.KeyBlob,
				serverPublicKey,
				signature,
			)

			kexDHReplyBytes, err := kexDHReply.Marshal()
			if err != nil {
				logger.Error("Failed to marshal KEXDH_REPLY: %v", err)
				return
			}

			err = packetConn.WritePacket(&transport.Packet{
				Type:    protocol.SSH_MSG_KEXDH_REPLY,
				Payload: kexDHReplyBytes[1:], // Skip the message type byte
			})
			if err != nil {
				logger.Error("Failed to send KEXDH_REPLY: %v", err)
				return
			}

			// Send new keys message
			newKeys := messages.NewNewKeysMessage()
			newKeysBytes, err := newKeys.Marshal()
			if err != nil {
				logger.Error("Failed to marshal NEWKEYS: %v", err)
				return
			}

			err = packetConn.WritePacket(&transport.Packet{
				Type:    protocol.SSH_MSG_NEWKEYS,
				Payload: newKeysBytes[1:], // Skip the message type byte
			})
			if err != nil {
				logger.Error("Failed to send NEWKEYS: %v", err)
				return
			}

			logger.Info("Key exchange initiated, waiting for client's NEWKEYS")

		case protocol.SSH_MSG_NEWKEYS:
			logger.Info("Received NEWKEYS from client")

			// Enable encryption
			packetConn.EnableEncryption()
			keyExchangeComplete = true
			logger.Info("Key exchange completed successfully with %s", remoteAddr)

		case protocol.SSH_MSG_IGNORE:
			// Ignore these messages (used for keep-alive)
			logger.Debug("Received keep-alive from client")

		case protocol.SSH_MSG_DISCONNECT:
			logger.Info("Client requested disconnect")
			return

		default:
			if !keyExchangeComplete {
				logger.Error("Received unexpected message type %d during key exchange", packet.Type)
				return
			}

			// Send SSH_MSG_UNIMPLEMENTED for unknown message types
			var buf bytes.Buffer
			messages.WriteUint32(&buf, packetConn.SequenceNumber-1)

			unimplementedPacket := &transport.Packet{
				Type:    protocol.SSH_MSG_UNIMPLEMENTED,
				Payload: buf.Bytes(),
			}

			if err := packetConn.WritePacket(unimplementedPacket); err != nil {
				logger.Error("Failed to send UNIMPLEMENTED: %v", err)
				return
			}
		}
	}
}
