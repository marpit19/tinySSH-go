package protocol

// SSH protocol version
const (
	ProtocolVersion = "SSH-2.0-TinySHH_Go"
)

// SSH Message Types (RFC 4253)
const (
	SSH_MSG_DISCONNECT            = 1
	SSH_MSG_IGNORE                = 2
	SSH_MSG_UNIMPLEMENTED         = 3
	SSH_MSG_DEBUG                 = 4
	SSH_MSG_SERVICE_REQUEST       = 5
	SSH_MSG_SERVICE_ACCEPT        = 6
	SSH_MSG_KEXINIT               = 20
	SSH_MSG_NEWKEYS               = 21
	SSH_MSG_KEXDH_INIT            = 30
	SSH_MSG_KEXDH_REPLY           = 31
	SSH_MSG_USERAUTH_REQUEST      = 50
	SSH_MSG_USERAUTH_FAILURE      = 51
	SSH_MSG_USERAUTH_SUCCESS      = 52
	SSH_MSG_USERAUTH_BANNER       = 53
	SSH_MSG_GLOBAL_REQUEST        = 80
	SSH_MSG_REQUEST_SUCCESS       = 81
	SSH_MSG_REQUEST_FAILURE       = 82
	SSH_MSG_CHANNEL_OPEN          = 90
	SSH_MSG_CHANNEL_OPEN_CONFIRM  = 91
	SSH_MSG_CHANNEL_OPEN_FAILURE  = 92
	SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
	SSH_MSG_CHANNEL_DATA          = 94
	SSH_MSG_CHANNEL_EXTENDED_DATA = 95
	SSH_MSG_CHANNEL_EOF           = 96
	SSH_MSG_CHANNEL_CLOSE         = 97
	SSH_MSG_CHANNEL_REQUEST       = 98
	SSH_MSG_CHANNEL_SUCCESS       = 99
	SSH_MSG_CHANNEL_FAILURE       = 100
)

// SSH Disconnect Reason Codes (RFC 4253)
const (
	SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    = 1
	SSH_DISCONNECT_PROTOCOL_ERROR                 = 2
	SSH_DISCONNECT_KEY_EXCHANGE_FAILED            = 3
	SSH_DISCONNECT_RESERVED                       = 4
	SSH_DISCONNECT_MAC_ERROR                      = 5
	SSH_DISCONNECT_COMPRESSION_ERROR              = 6
	SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          = 7
	SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
	SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        = 9
	SSH_DISCONNECT_CONNECTION_LOST                = 10
	SSH_DISCONNECT_BY_APPLICATION                 = 11
	SSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12
	SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13
	SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
	SSH_DISCONNECT_ILLEGAL_USER_NAME              = 15
)

// Default timeouts and limits
const (
	KeepAliveInterval = 60    // Seconds between keep-alive messages
	MaxPacketSize     = 35000 // Maximum SSH packet size
)
