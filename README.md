# TinySSH-Go

A minimalistic SSH server and client implementation in Go for educational purposes.

## Overview

TinySSH-Go is a simplified SSH implementation designed to demonstrate the core concepts of the SSH protocol. It's built as a learning project to understand the inner workings of SSH without the complexity of a production-ready implementation. The project supports basic SSH functionality including:

- SSH protocol version exchange
- Key exchange using Diffie-Hellman
- Password authentication
- Channel and session management
- Command execution

**Note:** This project is for educational purposes only and should not be used in production environments.

## Building and Running

### Prerequisites

- Go 1.22 or later
- Git

### Building

```bash
# Clone the repository
git clone https://github.com/marpit19/tinySSH-go.git
cd tinyssh-go

# Build the project
go build ./...
```

### Running the Server

```bash
go run cmd/server/main.go [options]
```

Server options:
- `-port` - Port to listen on (default: 2222)
- `-host` - Host to listen on (default: localhost)
- `-key` - Path to host key file (default: ssh_host_key)
- `-auth` - Path to credentials file (default: credentials.txt)

### Running the Client

```bash
go run cmd/client/main.go [options]
```

Client options:
- `-port` - Port to connect to (default: 2222)
- `-host` - Host to connect to (default: localhost)
- `-user` - Username for authentication (default: admin)
- `-pass` - Password for authentication (default: password)
- `-exec` - Command to execute on the server (default: interactive shell)

## Server Console Commands

The server provides a simple console interface with the following commands:

- `exit()` - Gracefully shut down the server
- `status` - Display active connections
- `help` - Show available commands

## Credentials File Format

The server can load user credentials from a file. The format is simple:

```
# Comments start with #
username:password
```

Example `credentials.txt`:
```
admin:password
testuser:testpass
```

## Demo Instructions

Here's how to demonstrate basic functionality:

### 1. Start the Server

```bash
go run cmd/server/main.go
```

You should see output like:
```
[2025-03-23 02:21:59.755] [INFO] [server] Starting TinySSH-Go server on localhost:2222
[2025-03-23 02:21:59.758] [INFO] [server] Server is listening for connections
```

### 2. Connect with the Client

In another terminal:

```bash
# Connect and start an interactive shell
go run cmd/client/main.go -user admin -pass password

# Or execute a specific command
go run cmd/client/main.go -user admin -pass password -exec "ls -la"
```

### 3. Try Server Commands

In the server terminal, try the console commands:

```
status
```

This will show current connections:
```
Active connections: 1
  - 127.0.0.1:12345
```

### 4. Testing Authentication

Try connecting with incorrect credentials:

```bash
go run cmd/client/main.go -user admin -pass wrongpassword
```

This should fail with an authentication error.

### 5. Shutting Down

In the server terminal:

```
exit()
```

## Implementation Details

TinySSH-Go implements the following components of the SSH protocol:

1. **TCP Connection Establishment**
   - Basic TCP socket handling
   - Connection logging

2. **SSH Protocol Version Exchange**
   - Protocol version identification (SSH-2.0-TinySSH_Go)
   - Banner handling

3. **Binary Packet Protocol**
   - Message framing
   - Padding
   - Keep-alive mechanism

4. **Key Exchange**
   - Diffie-Hellman key exchange
   - Session key derivation
   - Re-keying support

5. **Authentication**
   - Password authentication
   - Authentication failure handling
   - Brute-force protection

6. **Channel Management**
   - Session channels
   - Flow control with window size adjustments
   - Channel lifecycle management

7. **Command Execution**
   - Remote command execution
   - Standard input/output/error handling
   - Exit status reporting

## Development Roadmap

This project is being implemented in phases:

- [x] Phase 1: Project Setup & Basic Networking
- [x] Phase 2: SSH Protocol Basics
- [x] Phase 3: Simplified Key Exchange
- [x] Phase 4: Authentication Mechanism
- [x] Phase 5: Channel & Session Management
- [x] Phase 6: Command Execution
- [ ] Phase 7: Simple Terminal Support
- [ ] Phase 8: Client User Experience
- [ ] Phase 9: Documentation & Final Testing

## License

[MIT License](LICENSE)
