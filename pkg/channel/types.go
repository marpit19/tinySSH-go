package channel

// ChannelType defines the type of channel
type ChannelType string

// Channel types
const (
	SessionChannel ChannelType = "session"
	X11Channel     ChannelType = "x11"
	ForwardedTCPIP ChannelType = "forwarded-tcpip"
	DirectTCPIP    ChannelType = "direct-tcpip"
)

// ChannelStatus represents the current status of a channel
type ChannelStatus int

// Channel statuses
const (
	ChannelStatusNew ChannelStatus = iota
	ChannelStatusOpening
	ChannelStatusOpen
	ChannelStatusClosing
	ChannelStatusClosed
)

// String returns a string representation of ChannelStatus
func (s ChannelStatus) String() string {
	switch s {
	case ChannelStatusNew:
		return "new"
	case ChannelStatusOpening:
		return "opening"
	case ChannelStatusOpen:
		return "open"
	case ChannelStatusClosing:
		return "closing"
	case ChannelStatusClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// ChannelOpenFailureReason represents the reason for a channel open failure
type ChannelOpenFailureReason uint32

// Reasons for channel open failures
const (
	ChannelOpenAdministrativelyProhibited ChannelOpenFailureReason = 1
	ChannelOpenConnectFailed              ChannelOpenFailureReason = 2
	ChannelOpenUnknownChannelType         ChannelOpenFailureReason = 3
	ChannelOpenResourceShortage           ChannelOpenFailureReason = 4
)

// String returns a string representation of ChannelOpenFailureReason
func (r ChannelOpenFailureReason) String() string {
	switch r {
	case ChannelOpenAdministrativelyProhibited:
		return "administratively prohibited"
	case ChannelOpenConnectFailed:
		return "connect failed"
	case ChannelOpenUnknownChannelType:
		return "unknown channel type"
	case ChannelOpenResourceShortage:
		return "resource shortage"
	default:
		return "unknown"
	}
}

// DefaultWindowSize is the default initial window size
const DefaultWindowSize uint32 = 2097152 // 2MB

// DefaultMaxPacketSize is the default maximum packet size
const DefaultMaxPacketSize uint32 = 32768 // 32KB
