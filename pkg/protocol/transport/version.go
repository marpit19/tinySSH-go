package transport

import (
	"bufio"
	"fmt"
	"net"
	"strings"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
	"github.com/marpit19/tinySSH-go/pkg/protocol"
)

// ExchangeVersions performs the SSH protocol version exchange
func ExchangeVersions(conn net.Conn, logger *logging.Logger, isServer bool) (string, error) {
	reader := bufio.NewReader(conn)
	
	// each side MUST send its version string first if it's a server
	// clients should wait for server identification string
	var remoteVersion string
	var err error
	
	if isServer {
		// send our version string
		if err := sendVersion(conn); err != nil {
			return "", fmt.Errorf("failed to send version: %v", err)
		}
		
		// read their version string
		remoteVersion, err = readVersion(reader, logger)
		if err != nil {
			return "", fmt.Errorf("failed to read client version: %v", err)
		}
	} else {
		// read their version string
		remoteVersion, err = readVersion(reader, logger)
		if err != nil {
			return "", fmt.Errorf("failed to read server version: %v", err)
		}
		
		// send our version string
		if err := sendVersion(conn); err != nil {
			return "", fmt.Errorf("failed to send version: %v", err)
		}
	}
	
	logger.Info("Remote SSH version: %s", remoteVersion)
	return remoteVersion, nil
}

// sendVersion sends the SSH version string
func sendVersion(conn net.Conn) error {
	versionString := protocol.ProtocolVersion + "\r\n"
	_, err := conn.Write([]byte(versionString))
	return err
}

// readVersion reads and validates the SSH version string
func readVersion(reader *bufio.Reader, logger *logging.Logger) (string, error) {
	// acc. to RFC 4253, the version string must be less than 255 chars
	// including CRLF, so we use ReadLine to get a line of text
	for {
		line, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		
		// If isPrefix is true, the line was too long
		if isPrefix {
			return "", fmt.Errorf("version string too long")
		}
		
		versionStr := string(line)
		
		// skip lines that doesn't start with SSH- (allow for server banners)
		if !strings.HasPrefix(versionStr, "SSH-") {
			logger.Debug("Skipping non-version line: %s", versionStr)
			continue
		}
		
		// validate the version string
		parts := strings.SplitN(versionStr, "-", 3)
		if len(parts) < 3 {
			return "", fmt.Errorf("unsupported protocol version : %s", parts[1])
		}
		
		return versionStr, nil
	}
}
