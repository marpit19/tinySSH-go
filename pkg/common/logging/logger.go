package logging

import (
	"fmt"
	"log"
	"os"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
)

// Logger provides structured logging capabilities
type Logger struct {
	component string
	level     LogLevel
	logger    *log.Logger
}

// NewLogger creates a new logger for the specified component
func NewLogger(component string) *Logger {
	return &Logger{
		component: component,
		level:     INFO, // default level
		logger:    log.New(os.Stdout, "", 0),
	}
}

// SetLevel changes the current logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// formatMessage creates a formatted log message with timestamp and component
func (l *Logger) formatMessage(level string, format string, args ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf(format, args...)
	return fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, level, l.component, message)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= DEBUG {
		l.logger.Println(l.formatMessage("DEBUG", format, args...))
	}
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	if l.level <= WARNING {
		l.logger.Println(l.formatMessage("WARN", format, args...))
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= ERROR {
		l.logger.Println(l.formatMessage("ERROR", format, args...))
	}
}
