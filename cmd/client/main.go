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

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// read server response in a goroutine
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err.Error() == "EOF" {
					logger.Info("Server disconnected")
				} else {
					logger.Error("Error reading from server: %v", err)
				}
				os.Exit(0)
			}

			if n > 0 {
				logger.Debug("Received %d bytes from server", n)
				// just loggin the conn and not processing data
			}
		}
	}()

	// Main client loop
	// for now just wait for signal to exit
	<-sigChan
	logger.Info("Received signal, disconnecting....")
}
