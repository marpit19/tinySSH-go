package exec

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/marpit19/tinySSH-go/pkg/channel"
	"github.com/marpit19/tinySSH-go/pkg/common/logging"
)

// Command represents a command to be executed over an SSH channel
type Command struct {
	Command    string
	Args       []string
	Channel    *channel.Channel
	Logger     *logging.Logger
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	ExitStatus uint32
	cmd        *exec.Cmd
	started    bool
	finished   bool
	mu         sync.Mutex
}

// NewCommand creates a new command
func NewCommand(commandLine string, ch *channel.Channel, logger *logging.Logger) *Command {
	// Parse command and arguments
	parts := strings.Fields(commandLine)
	if len(parts) == 0 {
		return nil
	}

	command := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	return &Command{
		Command:    command,
		Args:       args,
		Channel:    ch,
		Logger:     logger,
		ExitStatus: 0,
		started:    false,
		finished:   false,
	}
}

// Start starts the command
func (c *Command) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("command already started")
	}

	c.Logger.Info("Starting command: %s %v", c.Command, c.Args)

	// Create the command
	c.cmd = exec.Command(c.Command, c.Args...)

	// Set up pipes for stdin, stdout, stderr
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// Connect pipes to channel or provided io.Reader/io.Writer
	c.Stdin = c.Channel
	c.Stdout = c.Channel
	c.Stderr = &stderrWrapper{c.Channel}

	// Start copying data in background goroutines
	go func() {
		io.Copy(stdin, c.Stdin)
		stdin.Close()
	}()

	go func() {
		io.Copy(c.Stdout, stdout)
	}()

	go func() {
		io.Copy(c.Stderr, stderr)
	}()

	// Start the command
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}

	c.started = true

	// Wait for command to complete in background
	go c.wait()

	return nil
}

// wait waits for the command to complete
func (c *Command) wait() {
	err := c.cmd.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		c.Logger.Error("Command failed: %v", err)

		// Get exit code if possible
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				c.ExitStatus = uint32(status.ExitStatus())
			} else {
				c.ExitStatus = 1
			}
		} else {
			c.ExitStatus = 1
		}
	} else {
		c.ExitStatus = 0
	}

	c.Logger.Info("Command completed with exit status: %d", c.ExitStatus)
	c.finished = true
}

// Kill terminates the command
func (c *Command) Kill() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started || c.finished {
		return nil
	}

	c.Logger.Info("Killing command")

	// Kill the process
	if err := c.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to kill command: %v", err)
	}

	return nil
}

// IsFinished checks if the command has finished
func (c *Command) IsFinished() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.finished
}

// GetExitStatus returns the exit status of the command
func (c *Command) GetExitStatus() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.ExitStatus
}

// stderrWrapper wraps a channel to send data as extended data (stderr)
type stderrWrapper struct {
	ch io.Writer
}

// Write implements io.Writer
func (w *stderrWrapper) Write(p []byte) (n int, err error) {
	// In a real implementation, we would use SSH_MSG_CHANNEL_EXTENDED_DATA
	// But for this simple implementation, we'll just prepend "[stderr] "
	data := append([]byte("[stderr] "), p...)
	return w.ch.Write(data)
}

// ExecuteInteractiveShell starts an interactive shell on the channel
func ExecuteInteractiveShell(ch *channel.Channel, logger *logging.Logger) error {
	logger.Info("Starting interactive shell")

	// Determine shell to use
	shell := os.Getenv("SHELL")
	if shell == "" {
		// Default to /bin/sh if $SHELL is not set
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell)
	cmd.Env = os.Environ()

	// Set up pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// Start copying data in background goroutines
	go func() {
		defer stdin.Close()
		io.Copy(stdin, ch)
	}()

	go func() {
		io.Copy(ch, stdout)
	}()

	go func() {
		var buf bytes.Buffer
		tee := io.TeeReader(stderr, &buf)
		io.Copy(ch, tee)
	}()

	// Start the shell
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	// Wait for shell to exit in a goroutine
	go func() {
		err := cmd.Wait()
		var exitStatus uint32 = 0

		if err != nil {
			logger.Error("Shell exited with error: %v", err)

			// Get exit code if possible
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					exitStatus = uint32(status.ExitStatus())
				} else {
					exitStatus = 1
				}
			} else {
				exitStatus = 1
			}
		}

		logger.Info("Shell exited with status: %d", exitStatus)

		// Close the channel
		ch.Close()
	}()

	return nil
}
