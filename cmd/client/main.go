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
	port := flag.Int("port", 2222, "Port to connect to")
	host := flag.String("host", "localhost", "Host to connect to")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// Initialize logger
	logger := logging.NewLogger("client")
	logger.Info("Connecting to %s", addr)

	// Connect to server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		logger.Error("Failed to connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	logger.Info("Connected to server at %s", addr)

	// Perform SSH version exchange
	remoteVersion, err := transport.ExchangeVersions(conn, logger, false)
	if err != nil {
		logger.Error("Version exchange failed: %v", err)
		os.Exit(1)
	}

	logger.Info("Server version: %s", remoteVersion)

	// Create packet connection
	packetConn := transport.NewPacketConn(conn, logger)

	// Start keep-alive mechanism
	packetConn.StartKeepAlive()

	// Set up a channel to receive packets
	packetChan := make(chan *transport.Packet)
	errChan := make(chan error)

	// Start goroutine to read packets
	go func() {
		for {
			packet, err := packetConn.ReadPacket()
			if err != nil {
				errChan <- err
				return
			}
			packetChan <- packet
		}
	}()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Main client loop
	for {
		select {
		case packet := <-packetChan:
			logger.Info("Received message type: %s", messages.MessageTypeString(packet.Type))

			// Handle different message types
			switch packet.Type {
			case protocol.SSH_MSG_KEXINIT:
				logger.Info("Received KEXINIT from server")

				// Send our Key Exchange Init
				kexInitMsg := messages.NewKexInitMessage()
				kexInitBytes, err := kexInitMsg.Marshal()
				if err != nil {
					logger.Error("Failed to marshal KEXINIT: %v", err)
					os.Exit(1)
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_KEXINIT,
					Payload: kexInitBytes[1:], // skip the message type byte
				})
				if err != nil {
					logger.Error("Failed to send KEXINIT: %v", err)
					os.Exit(1)
				}

			case protocol.SSH_MSG_IGNORE:
				// ignore these messages (used for keep-alive)
				logger.Debug("Received keep-alive from server")
			}
			
			case err := <-errChan:
			if err.Error() == "EOF" {
				logger.Info("Server disconnected")
			} else {
				logger.Error("Error reading from server: %v", err)
			}
			os.Exit(0)
			
			case sig := <-sigChan:
			logger.Info("Received signal: %v, disconnecting", sig)
			
			// Send disconnect message
			var buf  bytes.Buffer
			buf.WriteByte(protocol.SSH_DISCONNECT_BY_APPLICATION)
			messages.WriteString(&buf, "Client disconnecting")
			messages.WriteString(&buf, "")
			
			disconnectPacket := &transport.Packet{
				Type: protocol.SSH_MSG_DISCONNECT,
				Payload: buf.Bytes(),
			}
			
			if err := packetConn.WritePacket(disconnectPacket); err != nil {
				logger.Error("Failed to send disconnect message: %v", err)
			}
			
			os.Exit(0)
		}
	}
}
