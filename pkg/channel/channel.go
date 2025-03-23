package channel

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
)

// Channel represents an SSH channel
type Channel struct {
	channelType   ChannelType     // Type of the channel
	localID       uint32          // Local channel ID
	remoteID      uint32          // Remote channel ID
	localWindow   *Window         // Local flow control window
	remoteWindow  uint32          // Remote flow control window
	maxPacketSize uint32          // Maximum packet size
	status        ChannelStatus   // Current status
	logger        *logging.Logger // Logger
	incomingData  chan []byte     // Channel for incoming data
	outgoingData  chan []byte     // Channel for outgoing data
	closeOnce     sync.Once       // Ensure Close is called only once
	closed        chan struct{}   // Channel to signal closure
	mu            sync.Mutex      // Mutex for protecting state
}

// ChannelConfig contains configuration for a new channel
type ChannelConfig struct {
	ChannelType   ChannelType
	LocalID       uint32
	RemoteID      uint32
	InitialWindow uint32
	MaxWindow     uint32
	MaxPacketSize uint32
	Logger        *logging.Logger
}

// NewChannel creates a new SSH channel
func NewChannel(config ChannelConfig) *Channel {
	if config.InitialWindow == 0 {
		config.InitialWindow = DefaultWindowSize
	}

	if config.MaxWindow == 0 {
		config.MaxWindow = DefaultWindowSize
	}

	if config.MaxPacketSize == 0 {
		config.MaxPacketSize = DefaultMaxPacketSize
	}

	channel := &Channel{
		channelType:   config.ChannelType,
		localID:       config.LocalID,
		remoteID:      config.RemoteID,
		localWindow:   NewWindow(config.InitialWindow, config.MaxWindow),
		remoteWindow:  config.InitialWindow,
		maxPacketSize: config.MaxPacketSize,
		status:        ChannelStatusNew,
		logger:        config.Logger,
		incomingData:  make(chan []byte, 10), // Buffer some packets
		outgoingData:  make(chan []byte, 10), // Buffer some packets
		closed:        make(chan struct{}),
	}

	return channel
}

// LocalID returns the local channel ID
func (c *Channel) LocalID() uint32 {
	return c.localID
}

// RemoteID returns the remote channel ID
func (c *Channel) RemoteID() uint32 {
	return c.remoteID
}

// Type returns the channel type
func (c *Channel) Type() ChannelType {
	return c.channelType
}

// Status returns the current channel status
func (c *Channel) Status() ChannelStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.status
}

// SetStatus sets the channel status
func (c *Channel) SetStatus(status ChannelStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.status = status
	c.logger.Debug("Channel %d status changed to %s", c.localID, c.status.String())
}

// HandleData processes incoming data from the peer
func (c *Channel) HandleData(data []byte) error {
	c.mu.Lock()
	if c.status != ChannelStatusOpen {
		c.mu.Unlock()
		return fmt.Errorf("channel %d not open, current status: %s", c.localID, c.status.String())
	}
	c.mu.Unlock()

	// Check if within our window size
	if err := c.localWindow.Consume(uint32(len(data))); err != nil {
		return fmt.Errorf("flow control violation: %v", err)
	}

	// Send to data channel for processing
	select {
	case c.incomingData <- data:
		return nil
	case <-c.closed:
		return fmt.Errorf("channel closed")
	}
}

// Read reads data from the channel
func (c *Channel) Read(b []byte) (int, error) {
	select {
	case data := <-c.incomingData:
		n := copy(b, data)

		// If we couldn't fit everything, push the rest back
		if n < len(data) {
			select {
			case c.incomingData <- data[n:]:
			case <-c.closed:
				return n, io.EOF
			}
		}

		return n, nil

	case <-c.closed:
		return 0, io.EOF
	}
}

// Write writes data to the channel
func (c *Channel) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.status != ChannelStatusOpen {
		c.mu.Unlock()
		return 0, fmt.Errorf("channel %d not open, current status: %s", c.localID, c.status.String())
	}

	remoteWindow := atomic.LoadUint32(&c.remoteWindow)
	c.mu.Unlock()

	// Check if we have enough remote window space
	if uint32(len(b)) > remoteWindow {
		return 0, fmt.Errorf("not enough remote window space: %d < %d", remoteWindow, len(b))
	}

	// Send to outgoing data channel
	select {
	case c.outgoingData <- b:
		// Decrease remote window
		atomic.AddUint32(&c.remoteWindow, ^uint32(len(b)-1)) // This is a tricky way to subtract in Go
		return len(b), nil
	case <-c.closed:
		return 0, fmt.Errorf("channel closed")
	}
}

// Close closes the channel
func (c *Channel) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.status = ChannelStatusClosing
		c.mu.Unlock()

		close(c.closed)
		c.logger.Debug("Channel %d closed", c.localID)
	})

	return nil
}

// AdjustRemoteWindow adds to the remote window
func (c *Channel) AdjustRemoteWindow(increment uint32) {
	atomic.AddUint32(&c.remoteWindow, increment)
}

// NeedsWindowAdjustment checks if the local window needs adjustment
func (c *Channel) NeedsWindowAdjustment() bool {
	return c.localWindow.NeedsAdjustment()
}

// WindowAdjustmentSize returns the recommended window adjustment size
func (c *Channel) WindowAdjustmentSize() uint32 {
	return c.localWindow.AdjustmentSize()
}

// AdjustLocalWindow adjusts the local window
func (c *Channel) AdjustLocalWindow(increment uint32) uint32 {
	return c.localWindow.Add(increment)
}

// OutgoingData returns the channel for outgoing data
func (c *Channel) OutgoingData() <-chan []byte {
	return c.outgoingData
}

// SetRemoteID sets the remote channel ID
func (c *Channel) SetRemoteID(remoteID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.remoteID = remoteID
}
