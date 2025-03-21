package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
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

	// For now we will just be keeping the connetions open and log data received
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err.Error() == "EOF" {
				logger.Info("Client %s disconnected", remoteAddr)
			} else {
				logger.Error("Error reading from connection %s: %v", remoteAddr, err)
			}
			return
		}

		if n > 0 {
			logger.Debug("Receved %d bytes from %s", n, remoteAddr)
			// just logging not processing data
		}
	}
}
