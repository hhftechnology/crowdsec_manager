package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// defaultLogger is the global logger instance used throughout the application
var defaultLogger *logrus.Logger

// Init initializes the global logger with specified level and optional file output
// Creates log directories if they don't exist and sets up multi-writer for stdout and file
func Init(level, logFile string) {
	defaultLogger = logrus.New()

	// Parse and validate log level, fallback to info if invalid
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	defaultLogger.SetLevel(logLevel)

	// Use JSON formatter for structured logging with ISO 8601 timestamps
	defaultLogger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	// Configure output to both stdout and file for visibility and persistence
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if logFile != "" {
		// Create log directory if it doesn't exist
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err == nil {
			// Open log file with append mode to preserve existing logs
			if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
				writers = append(writers, file)
			}
		}
	}

	// Write to all configured outputs simultaneously
	multiWriter := io.MultiWriter(writers...)
	defaultLogger.SetOutput(multiWriter)
}

// argsToFields converts variadic key-value arguments to structured logging fields
// Expects arguments in pairs: key1, value1, key2, value2, ...
// Non-string keys are converted to strings
func argsToFields(args ...any) logrus.Fields {
	fields := make(logrus.Fields)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key, ok := args[i].(string)
			if !ok {
				key = fmt.Sprintf("%v", args[i])
			}
			fields[key] = args[i+1]
		}
	}
	return fields
}

// Debug logs a debug-level message with optional structured fields
func Debug(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Debug(msg)
	} else {
		defaultLogger.Debug(msg)
	}
}

// Info logs an info-level message with optional structured fields
func Info(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Info(msg)
	} else {
		defaultLogger.Info(msg)
	}
}

// Warn logs a warning-level message with optional structured fields
func Warn(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Warn(msg)
	} else {
		defaultLogger.Warn(msg)
	}
}

// Error logs an error-level message with optional structured fields
func Error(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Error(msg)
	} else {
		defaultLogger.Error(msg)
	}
}

// Fatal logs a fatal-level message with optional structured fields and exits with status 1
func Fatal(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Fatal(msg)
	} else {
		defaultLogger.Fatal(msg)
	}
}

// GinLogger returns a Gin middleware that logs HTTP requests with detailed metrics
// Logs: status code, method, path, client IP, latency, and response size
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request through the handler chain
		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		// Include query string in path for complete request logging
		if raw != "" {
			path = path + "?" + raw
		}

		// Log structured HTTP request metrics
		defaultLogger.WithFields(logrus.Fields{
			"status":  statusCode,
			"method":  method,
			"path":    path,
			"ip":      clientIP,
			"latency": latency,
			"size":    c.Writer.Size(),
		}).Info("HTTP Request")
	}
}
