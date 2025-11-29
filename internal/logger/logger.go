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

var defaultLogger *logrus.Logger

// Init initializes the global logger
func Init(level, logFile string) {
	defaultLogger = logrus.New()

	// Parse log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	defaultLogger.SetLevel(logLevel)

	// Set formatter to JSON
	defaultLogger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	// Create log file if specified
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err == nil {
			if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
				writers = append(writers, file)
			}
		}
	}

	// Create multi-writer
	multiWriter := io.MultiWriter(writers...)
	defaultLogger.SetOutput(multiWriter)
}

// argsToFields converts variadic arguments to logrus Fields
// It expects arguments in key-value pairs
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

// Debug logs a debug message
func Debug(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Debug(msg)
	} else {
		defaultLogger.Debug(msg)
	}
}

// Info logs an info message
func Info(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Info(msg)
	} else {
		defaultLogger.Info(msg)
	}
}

// Warn logs a warning message
func Warn(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Warn(msg)
	} else {
		defaultLogger.Warn(msg)
	}
}

// Error logs an error message
func Error(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Error(msg)
	} else {
		defaultLogger.Error(msg)
	}
}

// Fatal logs a fatal message and exits
func Fatal(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.WithFields(argsToFields(args...)).Fatal(msg)
	} else {
		defaultLogger.Fatal(msg)
	}
}

// GinLogger returns a gin middleware for logging
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get status code
		statusCode := c.Writer.Status()

		// Get client IP
		clientIP := c.ClientIP()

		// Get method
		method := c.Request.Method

		// Build path with query
		if raw != "" {
			path = path + "?" + raw
		}

		// Log request
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
