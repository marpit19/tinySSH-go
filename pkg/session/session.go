package session

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/marpit19/tinySSH-go/pkg/channel"
	"github.com/marpit19/tinySSH-go/pkg/common/logging"
)

// ChannelHandler is a function that handles new channels
type ChannelHandler func(channel *channel.Channel) error

// Session represents an SSH client session
type Session struct {
	username        string
	channels        map[uint32]*channel.Channel
	nextChannelID   uint32
	channelHandlers map[channel.ChannelType]ChannelHandler
	logger          *logging.Logger
	mu              sync.RWMutex
}

// NewSession creates a new SSH session
func NewSession(username string, logger *logging.Logger) *Session {
	return &Session{
		username:        username,
		channels:        make(map[uint32]*channel.Channel),
		nextChannelID:   0,
		channelHandlers: make(map[channel.ChannelType]ChannelHandler),
		logger:          logger,
	}
}

// Username returns the session username
func (s *Session) Username() string {
	return s.username
}

// RegisterChannelHandler registers a handler for a specific channel type
func (s *Session) RegisterChannelHandler(chanType channel.ChannelType, handler ChannelHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.channelHandlers[chanType] = handler
}

// NextChannelID gets the next available channel ID
func (s *Session) NextChannelID() uint32 {
	return atomic.AddUint32(&s.nextChannelID, 1)
}

// HandleChannelOpen handles an incoming channel open request
func (s *Session) HandleChannelOpen(
	chanType channel.ChannelType,
	senderChannel uint32,
	initialWindow uint32,
	maxPacketSize uint32,
) (uint32, error) {
	s.mu.RLock()
	handler, exists := s.channelHandlers[chanType]
	s.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("unsupported channel type: %s", chanType)
	}

	// Create new channel
	localID := s.NextChannelID()

	ch := channel.NewChannel(channel.ChannelConfig{
		ChannelType:   chanType,
		LocalID:       localID,
		RemoteID:      senderChannel,
		InitialWindow: initialWindow,
		MaxPacketSize: maxPacketSize,
		Logger:        s.logger,
	})

	// Register channel
	s.mu.Lock()
	s.channels[localID] = ch
	s.mu.Unlock()

	// Set status to opening
	ch.SetStatus(channel.ChannelStatusOpening)

	// Launch handler in background
	go func() {
		if err := handler(ch); err != nil {
			s.logger.Error("Channel handler error: %v", err)
			ch.Close()
		}
	}()

	return localID, nil
}

// OpenChannel opens a new channel to the peer
func (s *Session) OpenChannel(
	chanType channel.ChannelType,
	initialWindow uint32,
	maxPacketSize uint32,
) (*channel.Channel, uint32, error) {
	// Create new channel
	localID := s.NextChannelID()

	ch := channel.NewChannel(channel.ChannelConfig{
		ChannelType:   chanType,
		LocalID:       localID,
		RemoteID:      0, // Will be set when the confirmation is received
		InitialWindow: initialWindow,
		MaxPacketSize: maxPacketSize,
		Logger:        s.logger,
	})

	// Register channel
	s.mu.Lock()
	s.channels[localID] = ch
	s.mu.Unlock()

	// Set status to opening
	ch.SetStatus(channel.ChannelStatusOpening)

	return ch, localID, nil
}

// GetChannel gets a channel by ID
func (s *Session) GetChannel(id uint32) (*channel.Channel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ch, exists := s.channels[id]
	if !exists {
		return nil, fmt.Errorf("channel %d not found", id)
	}

	return ch, nil
}

// HandleChannelOpenConfirmation handles a channel open confirmation
func (s *Session) HandleChannelOpenConfirmation(localID, remoteID, initialWindow, maxPacketSize uint32) error {
	ch, err := s.GetChannel(localID)
	if err != nil {
		return err
	}

	if ch.Status() != channel.ChannelStatusOpening {
		return fmt.Errorf("channel %d not in opening state", localID)
	}

	// Set remote ID and window size
	ch.SetRemoteID(remoteID)
	ch.AdjustRemoteWindow(initialWindow)

	// Set channel as open
	ch.SetStatus(channel.ChannelStatusOpen)

	return nil
}

// HandleChannelOpenFailure handles a channel open failure
func (s *Session) HandleChannelOpenFailure(localID uint32, reason channel.ChannelOpenFailureReason, message string) error {
	ch, err := s.GetChannel(localID)
	if err != nil {
		return err
	}

	if ch.Status() != channel.ChannelStatusOpening {
		return fmt.Errorf("channel %d not in opening state", localID)
	}

	// Close the channel
	ch.Close()

	// Remove from channels map
	s.mu.Lock()
	delete(s.channels, localID)
	s.mu.Unlock()

	s.logger.Warning("Channel %d open failed: %s (%s)", localID, reason.String(), message)

	return nil
}

// HandleChannelClose handles a channel close request
func (s *Session) HandleChannelClose(localID uint32) error {
	ch, err := s.GetChannel(localID)
	if err != nil {
		return err
	}

	if ch.Status() == channel.ChannelStatusClosed {
		return nil // Already closed
	}

	// Close the channel
	ch.Close()

	// Set status to closed
	ch.SetStatus(channel.ChannelStatusClosed)

	// Remove from channels map
	s.mu.Lock()
	delete(s.channels, localID)
	s.mu.Unlock()

	return nil
}

// HandleChannelData handles data for a channel
func (s *Session) HandleChannelData(localID uint32, data []byte) error {
	ch, err := s.GetChannel(localID)
	if err != nil {
		return err
	}

	return ch.HandleData(data)
}

// HandleChannelWindowAdjust handles a window adjustment for a channel
func (s *Session) HandleChannelWindowAdjust(localID uint32, increment uint32) error {
	ch, err := s.GetChannel(localID)
	if err != nil {
		return err
	}

	ch.AdjustRemoteWindow(increment)

	return nil
}

// Close closes all channels in the session
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ch := range s.channels {
		ch.Close()
	}

	s.channels = make(map[uint32]*channel.Channel)

	return nil
}
