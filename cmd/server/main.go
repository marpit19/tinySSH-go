package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/marpit19/tinySSH-go/pkg/auth"
	"github.com/marpit19/tinySSH-go/pkg/auth/store"
	"github.com/marpit19/tinySSH-go/pkg/channel"
	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/crypto"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
	"github.com/marpit19/tinySSH-go/pkg/protocol/messages"
	"github.com/marpit19/tinySSH-go/pkg/protocol/transport"
	"github.com/marpit19/tinySSH-go/pkg/session"
)

var (
	hostKey             *crypto.HostKey
	connections         = make(map[string]*transport.PacketConn)
	connMutex           sync.Mutex
	shutdown            = make(chan struct{})
	authStore           auth.Authenticator
	bruteForceProtector *auth.BruteForceProtector
	sessions            = make(map[string]*session.Session) // Maps remoteAddr to session
	sessionMutex        sync.Mutex
	logger              *logging.Logger
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 2222, "Port to listen on")
	host := flag.String("host", "localhost", "Host to listen on")
	keyPath := flag.String("key", "ssh_host_key", "Path to host key file")
	authFilePath := flag.String("auth", "credentials.txt", "Path to credentials file")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// Initialize logger
	logger = logging.NewLogger("server")
	logger.Info("Starting TinySSH-Go server on %s", addr)

	// Load or generate host key
	var err error
	hostKey, err = crypto.LoadOrGenerateHostKey(*keyPath)
	if err != nil {
		logger.Error("Failed to load or generate host key: %v", err)
		os.Exit(1)
	}
	logger.Info("Host key loaded/generated successfully")

	// Initialize authentication
	bruteForceProtector = auth.NewBruteForceProtector(logger)

	// Try to load credentials from file
	authStore, err = store.NewFileAuthStore(*authFilePath, logger)
	if err != nil {
		logger.Warning("Failed to load authentication from file: %v", err)
		logger.Info("Using in-memory authentication store with default credentials")

		// Fall back to in-memory auth store with default credentials
		memStore := store.NewMemoryAuthStore()
		memStore.AddUser("admin", "password")
		authStore = memStore

		logger.Info("Added default user 'admin' with password 'password'")
	}

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
					// Check if the listener was closed
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

	// Start a goroutine to handle console commands
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

// handleConsoleCommands processes commands from the terminal
func handleConsoleCommands(logger *logging.Logger, listener net.Listener) {
	scanner := bufio.NewScanner(os.Stdin)
	logger.Info("Server command interface ready. Type 'exit()' to shutdown.")

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

// shutdownServer gracefully shuts down the server
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

	// Close all sessions
	sessionMutex.Lock()
	for addr, sess := range sessions {
		logger.Info("Closing session for %s", addr)
		sess.Close()
		delete(sessions, addr)
	}
	sessionMutex.Unlock()

	// Close listener
	logger.Info("Closing listener...")
	listener.Close()

	logger.Info("Server shutdown complete")
}

// handleConnection processes a client connection
func handleConnection(conn net.Conn, logger *logging.Logger) {
	remoteAddr := conn.RemoteAddr().String()
	logger.Info("New connection from %s", remoteAddr)

	// Check if IP is locked out due to too many failed authentication attempts
	if bruteForceProtector.IsLockedOut(conn) {
		logger.Warning("Connection from locked out IP %s rejected", remoteAddr)
		conn.Close()
		return
	}

	// Register connection
	connMutex.Lock()
	packetConn, err := transport.NewPacketConn(conn, logger, hostKey)
	if err != nil {
		logger.Error("Failed to create packet connection: %v", err)
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

		// Unregister session if exists
		sessionMutex.Lock()
		if userSession, ok := sessions[remoteAddr]; ok {
			userSession.Close()
			delete(sessions, remoteAddr)
		}
		sessionMutex.Unlock()

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
		Payload: serverKexInitBytes[1:], // Skip the message type byte
	})
	if err != nil {
		logger.Error("Failed to send KEXINIT: %v", err)
		return
	}

	// Variables to track connection state
	var clientKexInitBytes []byte
	var keyExchangeComplete bool
	var authenticated bool
	var username string
	var serviceRequested bool

	// Main packet processing loop
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

		case protocol.SSH_MSG_SERVICE_REQUEST:
			if !keyExchangeComplete {
				logger.Error("Received SERVICE_REQUEST before key exchange completion")
				return
			}

			// Parse service request
			serviceRequest := &messages.ServiceRequestMessage{}
			err := serviceRequest.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal SERVICE_REQUEST: %v", err)
				return
			}

			logger.Info("Client requested service: %s", serviceRequest.ServiceName)

			// Currently we only support the ssh-userauth service
			if serviceRequest.ServiceName != "ssh-userauth" {
				logger.Error("Unsupported service requested: %s", serviceRequest.ServiceName)
				return
			}

			// Send service accept
			serviceAccept := messages.NewServiceAcceptMessage(serviceRequest.ServiceName)
			serviceAcceptBytes, err := serviceAccept.Marshal()
			if err != nil {
				logger.Error("Failed to marshal SERVICE_ACCEPT: %v", err)
				return
			}

			err = packetConn.WritePacket(&transport.Packet{
				Type:    protocol.SSH_MSG_SERVICE_ACCEPT,
				Payload: serviceAcceptBytes[1:], // Skip the message type byte
			})
			if err != nil {
				logger.Error("Failed to send SERVICE_ACCEPT: %v", err)
				return
			}

			serviceRequested = true

		case protocol.SSH_MSG_USERAUTH_REQUEST:
			if !keyExchangeComplete || !serviceRequested {
				logger.Error("Received USERAUTH_REQUEST before key exchange or service request")
				return
			}

			// Parse authentication request
			authRequest := &messages.UserAuthRequestMessage{}
			err := authRequest.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal USERAUTH_REQUEST: %v", err)
				return
			}

			logger.Info("Authentication request: username=%s, method=%s",
				authRequest.Username, authRequest.MethodName)

			// Get allowed authentication methods for this user
			allowedMethods := authStore.GetAllowedMethods(authRequest.Username)

			// Check if method is allowed
			methodAllowed := false
			for _, method := range allowedMethods {
				if method == authRequest.MethodName {
					methodAllowed = true
					break
				}
			}

			if !methodAllowed {
				logger.Warning("Authentication method %s not allowed for user %s",
					authRequest.MethodName, authRequest.Username)

				// Send authentication failure
				authFailure := messages.NewUserAuthFailureMessage(allowedMethods, false)
				authFailureBytes, err := authFailure.Marshal()
				if err != nil {
					logger.Error("Failed to marshal USERAUTH_FAILURE: %v", err)
					return
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_USERAUTH_FAILURE,
					Payload: authFailureBytes[1:], // Skip the message type byte
				})
				if err != nil {
					logger.Error("Failed to send USERAUTH_FAILURE: %v", err)
					return
				}

				continue
			}

			// Handle different authentication methods
			authSuccess := false

			switch authRequest.MethodName {
			case "none":
				// The "none" method is always rejected
				authSuccess = false

			case "password":
				// Parse password authentication data
				passwordData, err := messages.UnmarshalPasswordRequestData(authRequest.MethodData)
				if err != nil {
					logger.Error("Failed to unmarshal password data: %v", err)
					return
				}

				// Authenticate
				authSuccess = authStore.AuthenticatePassword(authRequest.Username, passwordData.Password)

				// Record the authentication attempt
				if authSuccess {
					bruteForceProtector.RecordSuccessfulAttempt(conn)
					logger.Info("Password authentication successful for user %s", authRequest.Username)
					username = authRequest.Username
				} else {
					if !bruteForceProtector.RecordFailedAttempt(conn) {
						logger.Warning("Too many failed authentication attempts from %s", remoteAddr)
						return
					}
					logger.Warning("Password authentication failed for user %s", authRequest.Username)
				}

			default:
				logger.Warning("Unsupported authentication method: %s", authRequest.MethodName)
				authSuccess = false
			}

			// Send authentication response
			if authSuccess {
				// Create new session for this connection
				sessionMutex.Lock()
				userSession := session.NewSession(authRequest.Username, logger)
				sessions[remoteAddr] = userSession
				sessionMutex.Unlock()

				// Register handlers for channel types
				userSession.RegisterChannelHandler(channel.SessionChannel, handleSessionChannel)

				// Send authentication success
				authSuccess := messages.NewUserAuthSuccessMessage()
				authSuccessBytes, err := authSuccess.Marshal()
				if err != nil {
					logger.Error("Failed to marshal USERAUTH_SUCCESS: %v", err)
					return
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_USERAUTH_SUCCESS,
					Payload: authSuccessBytes[1:], // Skip the message type byte
				})
				if err != nil {
					logger.Error("Failed to send USERAUTH_SUCCESS: %v", err)
					return
				}

				authenticated = true
				logger.Info("User %s authenticated successfully", username)

			} else {
				// Send authentication failure
				authFailure := messages.NewUserAuthFailureMessage(allowedMethods, false)
				authFailureBytes, err := authFailure.Marshal()
				if err != nil {
					logger.Error("Failed to marshal USERAUTH_FAILURE: %v", err)
					return
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_USERAUTH_FAILURE,
					Payload: authFailureBytes[1:], // Skip the message type byte
				})
				if err != nil {
					logger.Error("Failed to send USERAUTH_FAILURE: %v", err)
					return
				}
			}

		case protocol.SSH_MSG_CHANNEL_OPEN:
			if !authenticated {
				logger.Error("Received CHANNEL_OPEN before authentication")
				return
			}

			// Parse channel open message
			channelOpen := &messages.ChannelOpenMessage{}
			err := channelOpen.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal CHANNEL_OPEN: %v", err)
				return
			}

			logger.Info("Received channel open request: type=%s, sender=%d, window=%d, max=%d",
				channelOpen.ChannelType, channelOpen.SenderChannel,
				channelOpen.InitialWindow, channelOpen.MaxPacketSize)

			// Get user's session
			sessionMutex.Lock()
			userSession, ok := sessions[remoteAddr]
			sessionMutex.Unlock()

			if !ok {
				logger.Error("No session found for %s", remoteAddr)
				return
			}

			// Handle channel open
			recipientChannel, err := userSession.HandleChannelOpen(
				channel.ChannelType(channelOpen.ChannelType),
				channelOpen.SenderChannel,
				channelOpen.InitialWindow,
				channelOpen.MaxPacketSize,
			)

			if err != nil {
				logger.Error("Failed to open channel: %v", err)

				// Send channel open failure
				failureMsg := messages.NewChannelOpenFailureMessage(
					channelOpen.SenderChannel,
					uint32(channel.ChannelOpenUnknownChannelType),
					err.Error(),
					"",
				)

				failureBytes, err := failureMsg.Marshal()
				if err != nil {
					logger.Error("Failed to marshal CHANNEL_OPEN_FAILURE: %v", err)
					return
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_CHANNEL_OPEN_FAILURE,
					Payload: failureBytes[1:],
				})
				if err != nil {
					logger.Error("Failed to send CHANNEL_OPEN_FAILURE: %v", err)
					return
				}
			} else {
				// Send channel open confirmation
				confirmMsg := messages.NewChannelOpenConfirmMessage(
					channelOpen.SenderChannel,
					recipientChannel,
					channel.DefaultWindowSize,
					channel.DefaultMaxPacketSize,
					nil,
				)

				confirmBytes, err := confirmMsg.Marshal()
				if err != nil {
					logger.Error("Failed to marshal CHANNEL_OPEN_CONFIRM: %v", err)
					return
				}

				err = packetConn.WritePacket(&transport.Packet{
					Type:    protocol.SSH_MSG_CHANNEL_OPEN_CONFIRM,
					Payload: confirmBytes[1:],
				})
				if err != nil {
					logger.Error("Failed to send CHANNEL_OPEN_CONFIRM: %v", err)
					return
				}

				logger.Info("Channel %d opened successfully", recipientChannel)
			}

		case protocol.SSH_MSG_CHANNEL_WINDOW_ADJUST:
			if !authenticated {
				logger.Error("Received CHANNEL_WINDOW_ADJUST before authentication")
				return
			}

			// Parse window adjust message
			windowAdjust := &messages.ChannelWindowAdjustMessage{}
			err := windowAdjust.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal CHANNEL_WINDOW_ADJUST: %v", err)
				return
			}

			// Get user's session
			sessionMutex.Lock()
			userSession, ok := sessions[remoteAddr]
			sessionMutex.Unlock()

			if !ok {
				logger.Error("No session found for %s", remoteAddr)
				return
			}

			// Handle window adjust
			err = userSession.HandleChannelWindowAdjust(windowAdjust.RecipientChannel, windowAdjust.BytesToAdd)
			if err != nil {
				logger.Error("Failed to adjust window: %v", err)
			} else {
				logger.Debug("Adjusted window for channel %d by %d bytes",
					windowAdjust.RecipientChannel, windowAdjust.BytesToAdd)
			}

		case protocol.SSH_MSG_CHANNEL_DATA:
			if !authenticated {
				logger.Error("Received CHANNEL_DATA before authentication")
				return
			}

			// Parse channel data message
			channelData := &messages.ChannelDataMessage{}
			err := channelData.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal CHANNEL_DATA: %v", err)
				return
			}

			// Get user's session
			sessionMutex.Lock()
			userSession, ok := sessions[remoteAddr]
			sessionMutex.Unlock()

			if !ok {
				logger.Error("No session found for %s", remoteAddr)
				return
			}

			// Handle channel data
			err = userSession.HandleChannelData(channelData.RecipientChannel, channelData.Data)
			if err != nil {
				logger.Error("Failed to handle channel data: %v", err)
			} else {
				logger.Debug("Received %d bytes for channel %d",
					len(channelData.Data), channelData.RecipientChannel)

				// Check if we need to adjust our window
				ch, err := userSession.GetChannel(channelData.RecipientChannel)
				if err == nil && ch.NeedsWindowAdjustment() {
					adjustment := ch.WindowAdjustmentSize()
					ch.AdjustLocalWindow(adjustment)

					// Send window adjustment
					adjustMsg := messages.NewChannelWindowAdjustMessage(
						ch.RemoteID(),
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
								ch.RemoteID(), adjustment)
						}
					}
				}
			}

		case protocol.SSH_MSG_CHANNEL_EOF:
			if !authenticated {
				logger.Error("Received CHANNEL_EOF before authentication")
				return
			}

			// Parse channel EOF message
			channelEOF := &messages.ChannelEOFMessage{}
			err := channelEOF.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal CHANNEL_EOF: %v", err)
				return
			}

			// Get user's session
			sessionMutex.Lock()
			userSession, ok := sessions[remoteAddr]
			sessionMutex.Unlock()

			if !ok {
				logger.Error("No session found for %s", remoteAddr)
				return
			}

			// Get the channel
			ch, err := userSession.GetChannel(channelEOF.RecipientChannel)
			if err != nil {
				logger.Error("Failed to get channel: %v", err)
				return
			}
			if ch == nil {
				logger.Debug("ch is nil right now...")
			}

			// Just log EOF for now
			logger.Info("Received EOF for channel %d", channelEOF.RecipientChannel)

		case protocol.SSH_MSG_CHANNEL_CLOSE:
			if !authenticated {
				logger.Error("Received CHANNEL_CLOSE before authentication")
				return
			}

			// Parse channel close message
			channelClose := &messages.ChannelCloseMessage{}
			err := channelClose.Unmarshal(append([]byte{packet.Type}, packet.Payload...))
			if err != nil {
				logger.Error("Failed to unmarshal CHANNEL_CLOSE: %v", err)
				return
			}

			// Get user's session
			sessionMutex.Lock()
			userSession, ok := sessions[remoteAddr]
			sessionMutex.Unlock()

			if !ok {
				logger.Error("No session found for %s", remoteAddr)
				return
			}

			// Handle channel close
			err = userSession.HandleChannelClose(channelClose.RecipientChannel)
			if err != nil {
				logger.Error("Failed to close channel: %v", err)
			} else {
				logger.Info("Channel %d closed", channelClose.RecipientChannel)

				// Send our own close message
				closeMsg := messages.NewChannelCloseMessage(channelClose.RecipientChannel)
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
			}

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

			if !authenticated {
				logger.Error("Received message type %d before authentication", packet.Type)
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

// handleSessionChannel handles a "session" type channel
func handleSessionChannel(ch *channel.Channel) error {
	logger.Info("New session channel %d", ch.LocalID())

	// Set channel as open
	ch.SetStatus(channel.ChannelStatusOpen)

	// Process data from this channel
	for {
		// Read data in a blocking mode
		buffer := make([]byte, 1024)
		n, err := ch.Read(buffer)
		if err != nil {
			if err == io.EOF {
				logger.Info("Channel %d EOF", ch.LocalID())
				break
			}
			return fmt.Errorf("error reading from channel: %v", err)
		}

		if n > 0 {
			logger.Debug("Read %d bytes from channel %d", n, ch.LocalID())

			// Echo back for now (we'll replace this with proper command execution in Phase 6)
			_, err = ch.Write(buffer[:n])
			if err != nil {
				return fmt.Errorf("error writing to channel: %v", err)
			}
		}
	}

	return nil
}
