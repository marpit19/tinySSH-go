package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
	"github.com/marpit19/tinySSH-go/pkg/protocol/messages"
	"github.com/marpit19/tinySSH-go/pkg/protocol/transport"
)

func main() {
	// Parse cli flags
	port := flag.Int("port", 2222, "Port to listen on")
	host := flag.String("host", "localhost", "Host to listen on")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// Initalize logger
	logger := logging.NewLogger("server")
	logger.Info("Starting TinySSH-Go server on %s", addr)

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
				if opErr, ok := err.(*net.OpError); ok {
					if opErr.Err.Error() == "use of closed network connection" {
						return
					}
				}
				logger.Error("Error accepting connection: %v", err)
				continue
			}
			connChan <- conn
		}
	}()

	// Main server loop
	for {
		select {
		case conn := <-connChan:
			// Handle each connection in a new goroutine
			go handleConnection(conn, logger)

		}
	}
}

// handleConnection processes a new client connection
func handleConnection(conn net.Conn, logger *logging.Logger) {
	remoteAddr := conn.RemoteAddr().String()
	logger.Info("New connection from %s", remoteAddr)

	defer func() {
		conn.Close()
		logger.Info("Connection from %s closed", remoteAddr)
	}()

	// Perform SSH version exchange
	remoteVersion, err := transport.ExchangeVersions(conn, logger, true)
	if err != nil {
		logger.Error("Version exchange failed with %s: %v", remoteAddr, err)
		return
	}

	logger.Info("Client %s version: %s", remoteAddr, remoteVersion)

	// Create packet connection
	packetConn := transport.NewPacketConn(conn, logger)

	// Start keep-alive mechanism
	packetConn.StartKeepAlive()

	// Send Key Exchange Init
	kexInitMsg := messages.NewKexInitMessage()
	kexInitBytes, err := kexInitMsg.Marshal()
	if err != nil {
		logger.Error("failed to marshal KEXINIT: %v", err)
		return
	}

	err = packetConn.WritePacket(&transport.Packet{
		Type:    protocol.SSH_MSG_KEXINIT,
		Payload: kexInitBytes[1:], // skip the message type byte which is included in Marshal()
	})
	if err != nil {
		logger.Error("Failed to send KEXINIT: %v", err)
		return
	}

	// Main packet processing loop
	for {
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
		// right now we are just acknowledging recept but not fully processing it

		case protocol.SSH_MSG_IGNORE:
			// Ignore these messages (used for keep-alive)
			logger.Debug("Received keep-alive from client")

		case protocol.SSH_MSG_DISCONNECT:
			logger.Info("Client requested disconnect")
			return

		default:
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
