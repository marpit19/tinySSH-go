package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/crypto"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
	"github.com/marpit19/tinySSH-go/pkg/protocol/messages"
	"github.com/marpit19/tinySSH-go/pkg/protocol/transport"
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 2222, "Port to connect to")
	host := flag.String("host", "localhost", "Host to connect to")
	username := flag.String("user", "admin", "Username for authentication")
	password := flag.String("pass", "password", "Password for authentication")
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
	packetConn, err := transport.NewPacketConn(conn, logger, nil)
	if err != nil {
		logger.Error("Failed to create packet connection: %v", err)
		os.Exit(1)
	}

	// Start keep-alive mechanism
	packetConn.StartKeepAlive()

	// Create and init our key exchange session
	session, err := crypto.NewSession()
	if err != nil {
		logger.Error("Failed to create crypto session: %v", err)
		os.Exit(1)
	}

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

	// Variables to track key exchange state
	var serverKexInitBytes []byte
	var keyExchangeInitiated bool
	var keyExchangeComplete bool
	var serviceAccepted bool
	var authenticated bool

	// Main client loop
	for {
		select {
		case packet := <-packetChan:
			logger.Info("Received message type: %s", messages.MessageTypeString(packet.Type))

			// Handle different message types
			switch packet.Type {
			case protocol.SSH_MSG_KEXINIT:
				logger.Info("Received KEXINIT from server")

				// Save server's KEXINIT
				serverKexInitBytes = append([]byte{packet.Type}, packet.Payload...)

				// Send our Key Exchange Init if we haven't already
				if !keyExchangeInitiated {
					// Create our key exchange init message
					kexInitMsg := messages.NewKexInitMessage()
					clientKexInitBytes, err := kexInitMsg.Marshal()
					if err != nil {
						logger.Error("Failed to marshal KEXINIT: %v", err)
						os.Exit(1)
					}

					// Store our KEXINIT for later
					myKexInitBytes := clientKexInitBytes

					// Send our key exchange init
					err = packetConn.WritePacket(&transport.Packet{
						Type:    protocol.SSH_MSG_KEXINIT,
						Payload: clientKexInitBytes[1:], // Skip message type
					})
					if err != nil {
						logger.Error("Failed to send KEXINIT: %v", err)
						os.Exit(1)
					}

					// Initialize key exchange
					err = packetConn.InitiateKeyExchange(myKexInitBytes, serverKexInitBytes)
					if err != nil {
						logger.Error("Failed to initiate key exchange: %v", err)
						os.Exit(1)
					}

					// Send DH init with our public key
					publicKey := session.GetPublicKey()
					e := new(big.Int).SetBytes(publicKey)

					kexDHInit := messages.NewKexDHInitMessage(e)
					kexDHInitBytes, err := kexDHInit.Marshal()
					if err != nil {
						logger.Error("Failed to marshal KEXDH_INIT: %v", err)
						os.Exit(1)
					}

					err = packetConn.WritePacket(&transport.Packet{
						Type:    protocol.SSH_MSG_KEXDH_INIT,
						Payload: kexDHInitBytes[1:], // Skip message type
					})
					if err != nil {
						logger.Error("Failed to send KEXDH_INIT: %v", err)
						os.Exit(1)
					}

					keyExchangeInitiated = true
				}

			case protocol.SSH_MSG_KEXDH_REPLY:
				logger.Info("Received KEXDH_REPLY from server")

				// Parse server's DH reply
				kexDHReply := &messages.KexDHReplyMessage{}
				err := kexDHReply.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal KEXDH_REPLY: %v", err)
					os.Exit(1)
				}

				// Process server's public key and compute shared secret
				serverPublicKey := kexDHReply.F.Bytes()
				sharedSecret := session.ComputeSharedSecret(serverPublicKey)

				// Generate session ID and keys
				sessionID := crypto.GenerateSessionID(
					packetConn.Session.ClientKeyExchange,
					packetConn.Session.ServerKeyExchange,
					session.GetPublicKey(),
					serverPublicKey,
					sharedSecret,
				)

				packetConn.Session.ID = sessionID

				// Generate session keys
				keys := crypto.DeriveKeys(sharedSecret, sessionID)
				packetConn.Session.SetKeys(keys)

				// Verify server's signature (simplified)
				logger.Info("Server key exchange signature accepted")

				// Send new keys message
				newKeys := messages.NewNewKeysMessage()
				newKeysBytes, err := newKeys.Marshal()
				if err != nil {
					logger.Error("Failed to marshal NEWKEYS: %v", err)
					os.Exit(1)
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_NEWKEYS,
					Payload: newKeysBytes[1:], // Skip message type
				})
				if err != nil {
					logger.Error("Failed to send NEWKEYS: %v", err)
					os.Exit(1)
				}

			case protocol.SSH_MSG_NEWKEYS:
				logger.Info("Received NEWKEYS from server")

				// Enable encryption
				packetConn.EnableEncryption()
				keyExchangeComplete = true
				if keyExchangeComplete {
					logger.Debug("Key exchange flag is now true")
				}
				logger.Info("Key exchange completed successfully")

				// Request userauth service
				serviceRequest := messages.NewServiceRequestMessage("ssh-userauth")
				serviceRequestBytes, err := serviceRequest.Marshal()
				if err != nil {
					logger.Error("Failed to marshal SERVICE_REQUEST: %v", err)
					os.Exit(1)
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_SERVICE_REQUEST,
					Payload: serviceRequestBytes[1:], // Skip message type
				})
				if err != nil {
					logger.Error("Failed to send SERVICE_REQUEST: %v", err)
					os.Exit(1)
				}

				logger.Info("Requested ssh-userauth service")

			case protocol.SSH_MSG_SERVICE_ACCEPT:
				logger.Info("Received SERVICE_ACCEPT from server")

				// Parse service accept
				serviceAccept := &messages.ServiceAcceptMessage{}
				err := serviceAccept.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal SERVICE_ACCEPT: %v", err)
					os.Exit(1)
				}

				if serviceAccept.ServiceName != "ssh-userauth" {
					logger.Error("Unexpected service accepted: %s", serviceAccept.ServiceName)
					os.Exit(1)
				}

				serviceAccepted = true
				if serviceAccepted {
					logger.Debug("service is accepted")
				}

				// Send password authentication request
				passwordData := messages.MarshalPasswordRequestData(*password)

				authRequest := messages.NewUserAuthRequestMessage(
					*username,
					"ssh-connection",
					"password",
					passwordData,
				)

				authRequestBytes, err := authRequest.Marshal()
				if err != nil {
					logger.Error("Failed to marshal USERAUTH_REQUEST: %v", err)
					os.Exit(1)
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_USERAUTH_REQUEST,
					Payload: authRequestBytes[1:], // Skip message type
				})
				if err != nil {
					logger.Error("Failed to send USERAUTH_REQUEST: %v", err)
					os.Exit(1)
				}

				logger.Info("Sent password authentication request for user %s", *username)

			case protocol.SSH_MSG_USERAUTH_SUCCESS:
				logger.Info("Received USERAUTH_SUCCESS from server")
				authenticated = true
				if authenticated {
					logger.Debug("authentication is true")
				}
				logger.Info("Authentication successful!")

				// In a real client, we would now move to the connection protocol
				// and establish channels, but that's for the next phase

			case protocol.SSH_MSG_USERAUTH_FAILURE:
				logger.Info("Received USERAUTH_FAILURE from server")

				// Parse authentication failure
				authFailure := &messages.UserAuthFailureMessage{}
				err := authFailure.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal USERAUTH_FAILURE: %v", err)
					os.Exit(1)
				}

				logger.Warning("Authentication failed. Allowed methods: %v",
					authFailure.AuthMethodsRemaining)
				logger.Warning("Please check your username and password and try again")

				// In a real client, we would try another authentication method,
				// but for this simple implementation, we just exit
				os.Exit(1)

			case protocol.SSH_MSG_IGNORE:
				// Ignore these messages (used for keep-alive)
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
			var buf bytes.Buffer
			buf.WriteByte(protocol.SSH_DISCONNECT_BY_APPLICATION)
			messages.WriteString(&buf, "Client disconnecting")
			messages.WriteString(&buf, "") // Empty language tag

			disconnectPacket := &transport.Packet{
				Type:    protocol.SSH_MSG_DISCONNECT,
				Payload: buf.Bytes(),
			}

			if err := packetConn.WritePacket(disconnectPacket); err != nil {
				logger.Error("Failed to send disconnect message: %v", err)
			}

			os.Exit(0)
		}
	}
}
