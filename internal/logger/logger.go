package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// defaultLogger is the global zap logger instance used throughout the application
var defaultLogger *zap.Logger

// Init initializes the global logger with specified level and optional file output
// Creates log directories if they don't exist and sets up multi-writer for stdout and file
func Init(level, logFile string) {
	// Parse and validate log level, fallback to info if invalid
	zapLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		zapLevel = zapcore.InfoLevel
	}

	// JSON encoder with RFC3339 timestamps
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	encoderConfig.EncodeDuration = zapcore.StringDurationEncoder

	encoder := zapcore.NewJSONEncoder(encoderConfig)

	// Configure output to both stdout and file for visibility and persistence
	var cores []zapcore.Core
	cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapLevel))

	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err == nil {
			if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
				cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(file), zapLevel))
			}
		}
	}

	defaultLogger = zap.New(zapcore.NewTee(cores...))
}

// Sync flushes any buffered log entries. Should be called before application exit.
func Sync() {
	if defaultLogger != nil {
		_ = defaultLogger.Sync()
	}
}

// argsToFields converts variadic key-value arguments to zap fields
// Expects arguments in pairs: key1, value1, key2, value2, ...
// Non-string keys are converted to strings
func argsToFields(args ...any) []zap.Field {
	fields := make([]zap.Field, 0, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key, ok := args[i].(string)
			if !ok {
				key = fmt.Sprintf("%v", args[i])
			}
			fields = append(fields, zap.Any(key, args[i+1]))
		}
	}
	return fields
}

// Debug logs a debug-level message with optional structured fields
func Debug(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.Debug(msg, argsToFields(args...)...)
	} else {
		defaultLogger.Debug(msg)
	}
}

// Info logs an info-level message with optional structured fields
func Info(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.Info(msg, argsToFields(args...)...)
	} else {
		defaultLogger.Info(msg)
	}
}

// Warn logs a warning-level message with optional structured fields
func Warn(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.Warn(msg, argsToFields(args...)...)
	} else {
		defaultLogger.Warn(msg)
	}
}

// Error logs an error-level message with optional structured fields
func Error(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.Error(msg, argsToFields(args...)...)
	} else {
		defaultLogger.Error(msg)
	}
}

// Fatal logs a fatal-level message with optional structured fields and exits with status 1
func Fatal(msg string, args ...any) {
	if len(args) > 0 {
		defaultLogger.Fatal(msg, argsToFields(args...)...)
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
		defaultLogger.Info("HTTP Request",
			zap.Int("status", statusCode),
			zap.String("method", method),
			zap.String("path", path),
			zap.String("ip", clientIP),
			zap.Duration("latency", latency),
			zap.Int("size", c.Writer.Size()),
		)
	}
}
