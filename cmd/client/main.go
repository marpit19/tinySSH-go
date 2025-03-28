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

	"github.com/marpit19/tinySSH-go/pkg/channel"
	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/crypto"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
	"github.com/marpit19/tinySSH-go/pkg/protocol/messages"
	"github.com/marpit19/tinySSH-go/pkg/protocol/transport"
)

var (
	activeChannel *channel.Channel
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 2222, "Port to connect to")
	host := flag.String("host", "localhost", "Host to connect to")
	username := flag.String("user", "admin", "Username for authentication")
	password := flag.String("pass", "password", "Password for authentication")
	execCommand := flag.String("exec", "", "Command to execute on the server")
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

	// Create packet connection (without host key since client doesn't need one)
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

	// Variables to track connection state
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
					logger.Debug("serviceAccepted variable is now true")
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
					logger.Debug("authenticated is now true")
				}
				logger.Info("Authentication successful!")

				// Open a session channel
				channelType := string(channel.SessionChannel)
				senderChannel := uint32(0) // We'll increment this for each channel

				// Create channel open message
				channelOpen := messages.NewChannelOpenMessage(
					channelType,
					senderChannel,
					channel.DefaultWindowSize,
					channel.DefaultMaxPacketSize,
					nil,
				)

				channelOpenBytes, err := channelOpen.Marshal()
				if err != nil {
					logger.Error("Failed to marshal CHANNEL_OPEN: %v", err)
					os.Exit(1)
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_CHANNEL_OPEN,
					Payload: channelOpenBytes[1:],
				})
				if err != nil {
					logger.Error("Failed to send CHANNEL_OPEN: %v", err)
					os.Exit(1)
				}

				logger.Info("Requested channel open: type=%s, id=%d", channelType, senderChannel)

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

			case protocol.SSH_MSG_CHANNEL_OPEN_CONFIRM:
				logger.Info("Received CHANNEL_OPEN_CONFIRM from server")

				// Parse channel open confirm
				channelConfirm := &messages.ChannelOpenConfirmMessage{}
				err := channelConfirm.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_OPEN_CONFIRM: %v", err)
					os.Exit(1)
				}

				logger.Info("Channel %d confirmed, remote id=%d",
					channelConfirm.RecipientChannel, channelConfirm.SenderChannel)

				// Create channel object
				activeChannel = channel.NewChannel(channel.ChannelConfig{
					ChannelType:   channel.SessionChannel,
					LocalID:       channelConfirm.RecipientChannel,
					RemoteID:      channelConfirm.SenderChannel,
					InitialWindow: channelConfirm.InitialWindow,
					MaxPacketSize: channelConfirm.MaxPacketSize,
					Logger:        logger,
				})

				activeChannel.SetStatus(channel.ChannelStatusOpen)

				// Send some test data
				testData := []byte("Hello from TinySSH-Go client!\n")

				dataMsg := messages.NewChannelDataMessage(
					activeChannel.RemoteID(),
					testData,
				)

				dataBytes, err := dataMsg.Marshal()
				if err != nil {
					logger.Error("Failed to marshal CHANNEL_DATA: %v", err)
					os.Exit(1)
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_CHANNEL_DATA,
					Payload: dataBytes[1:],
				})
				if err != nil {
					logger.Error("Failed to send CHANNEL_DATA: %v", err)
					os.Exit(1)
				}

				// Update window
				activeChannel.AdjustRemoteWindow(^uint32(len(testData) - 1))

				// If a command was specified, send exec request
				if *execCommand != "" {
					logger.Info("Sending exec request: %s", *execCommand)

					// Create exec request data
					execData := messages.MarshalExecRequestData(*execCommand)

					// Create channel request message
					requestMsg := messages.NewChannelRequestMessage(
						activeChannel.RemoteID(),
						"exec",
						true, // want reply
						execData,
					)

					requestBytes, err := requestMsg.Marshal()
					if err != nil {
						logger.Error("Failed to marshal CHANNEL_REQUEST: %v", err)
						os.Exit(1)
					}

					err = packetConn.WritePacket(&transport.Packet{
						Type:    protocol.SSH_MSG_CHANNEL_REQUEST,
						Payload: requestBytes[1:],
					})
					if err != nil {
						logger.Error("Failed to send CHANNEL_REQUEST: %v", err)
						os.Exit(1)
					}
				} else {
					// If no command specified, send shell request
					logger.Info("Sending shell request")

					// Create channel request message
					requestMsg := messages.NewChannelRequestMessage(
						activeChannel.RemoteID(),
						"shell",
						true, // want reply
						nil,
					)

					requestBytes, err := requestMsg.Marshal()
					if err != nil {
						logger.Error("Failed to marshal CHANNEL_REQUEST: %v", err)
						os.Exit(1)
					}

					err = packetConn.WritePacket(&transport.Packet{
						Type:    protocol.SSH_MSG_CHANNEL_REQUEST,
						Payload: requestBytes[1:],
					})
					if err != nil {
						logger.Error("Failed to send CHANNEL_REQUEST: %v", err)
						os.Exit(1)
					}
				}

			case protocol.SSH_MSG_CHANNEL_OPEN_FAILURE:
				logger.Info("Received CHANNEL_OPEN_FAILURE from server")

				// Parse channel open failure
				channelFailure := &messages.ChannelOpenFailureMessage{}
				err := channelFailure.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_OPEN_FAILURE: %v", err)
					os.Exit(1)
				}

				logger.Error("Channel %d open failed: code=%d, reason=%s",
					channelFailure.RecipientChannel, channelFailure.ReasonCode,
					channelFailure.Description)

				os.Exit(1)

			case protocol.SSH_MSG_CHANNEL_WINDOW_ADJUST:
				// Parse window adjust message
				windowAdjust := &messages.ChannelWindowAdjustMessage{}
				err := windowAdjust.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_WINDOW_ADJUST: %v", err)
					continue
				}

				if activeChannel != nil && windowAdjust.RecipientChannel == activeChannel.LocalID() {
					activeChannel.AdjustRemoteWindow(windowAdjust.BytesToAdd)
					logger.Debug("Adjusted window for channel %d by %d bytes",
						windowAdjust.RecipientChannel, windowAdjust.BytesToAdd)
				}

			case protocol.SSH_MSG_CHANNEL_DATA:
				// Parse channel data message
				channelData := &messages.ChannelDataMessage{}
				err := channelData.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_DATA: %v", err)
					continue
				}

				if activeChannel != nil && channelData.RecipientChannel == activeChannel.LocalID() {
					logger.Info("Received data on channel %d: %s",
						channelData.RecipientChannel, string(channelData.Data))

					// Consume window space
					if err := activeChannel.HandleData(channelData.Data); err != nil {
						logger.Error("Error handling channel data: %v", err)
					}

					// Check if we need to adjust our window
					if activeChannel.NeedsWindowAdjustment() {
						adjustment := activeChannel.WindowAdjustmentSize()
						activeChannel.AdjustLocalWindow(adjustment)

						// Send window adjustment
						adjustMsg := messages.NewChannelWindowAdjustMessage(
							activeChannel.RemoteID(),
							adjustment,
						)

						adjustBytes, err := adjustMsg.Marshal()
						if err != nil {
							logger.Error("Failed to marshal CHANNEL_WINDOW_ADJUST: %v", err)
						} else {
							err = packetConn.WritePacket(&transport.Packet{
								Type:    protocol.SSH_MSG_CHANNEL_WINDOW_ADJUST,
								Payload: adjustBytes[1:],
							})
							if err != nil {
								logger.Error("Failed to send CHANNEL_WINDOW_ADJUST: %v", err)
							} else {
								logger.Debug("Adjusted window for channel %d by %d bytes",
									activeChannel.RemoteID(), adjustment)
							}
						}
					}
				}

			case protocol.SSH_MSG_CHANNEL_EOF:
				// Parse channel EOF message
				channelEOF := &messages.ChannelEOFMessage{}
				err := channelEOF.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_EOF: %v", err)
					continue
				}

				if activeChannel != nil && channelEOF.RecipientChannel == activeChannel.LocalID() {
					logger.Info("Received EOF for channel %d", channelEOF.RecipientChannel)
				}

			case protocol.SSH_MSG_CHANNEL_CLOSE:
				// Parse channel close message
				channelClose := &messages.ChannelCloseMessage{}
				err := channelClose.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_CLOSE: %v", err)
					continue
				}

				if activeChannel != nil && channelClose.RecipientChannel == activeChannel.LocalID() {
					logger.Info("Channel %d closed by server", channelClose.RecipientChannel)

					// Close our end too
					activeChannel.Close()

					// Send our own close message
					closeMsg := messages.NewChannelCloseMessage(activeChannel.RemoteID())
					closeBytes, err := closeMsg.Marshal()
					if err != nil {
						logger.Error("Failed to marshal CHANNEL_CLOSE: %v", err)
					} else {
						err = packetConn.WritePacket(&transport.Packet{
							Type:    protocol.SSH_MSG_CHANNEL_CLOSE,
							Payload: closeBytes[1:],
						})
						if err != nil {
							logger.Error("Failed to send CHANNEL_CLOSE: %v", err)
						}
					}

					activeChannel = nil
				}

				// Add these cases to process request replies
			case protocol.SSH_MSG_CHANNEL_SUCCESS:
				// Parse channel success message
				channelSuccess := &messages.ChannelSuccessMessage{}
				err := channelSuccess.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_SUCCESS: %v", err)
					continue
				}

				logger.Info("Channel request succeeded for channel %d", channelSuccess.RecipientChannel)

			case protocol.SSH_MSG_CHANNEL_FAILURE:
				// Parse channel failure message
				channelFailure := &messages.ChannelFailureMessage{}
				err := channelFailure.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
				if err != nil {
					logger.Error("Failed to unmarshal CHANNEL_FAILURE: %v", err)
					continue
				}

				logger.Error("Channel request failed for channel %d", channelFailure.RecipientChannel)
				if *execCommand != "" {
					logger.Error("Failed to execute command: %s", *execCommand)
					os.Exit(1)
				}

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

			// Close channel if active
			if activeChannel != nil {
				// Send channel close message
				closeMsg := messages.NewChannelCloseMessage(activeChannel.RemoteID())
				closeBytes, err := closeMsg.Marshal()
				if err != nil {
					logger.Error("Failed to marshal CHANNEL_CLOSE: %v", err)
				} else {
					err = packetConn.WritePacket(&transport.Packet{
						Type:    protocol.SSH_MSG_CHANNEL_CLOSE,
						Payload: closeBytes[1:],
					})
					if err != nil {
						logger.Error("Failed to send CHANNEL_CLOSE: %v", err)
					}
				}

				activeChannel.Close()
			}

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
