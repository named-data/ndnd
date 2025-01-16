package log

import "os"

var defaultLogger *Logger = NewText(os.Stderr)

// Default returns the default logger.
func Default() *Logger {
	return defaultLogger
}

// Trace level message.
func Trace(t Tag, msg string, v ...any) {
	defaultLogger.log(t, msg, LevelTrace, v...)
}

// Debug level message.
func Debug(t Tag, msg string, v ...any) {
	defaultLogger.log(t, msg, LevelDebug, v...)
}

// Info level message.
func Info(t Tag, msg string, v ...any) {
	defaultLogger.log(t, msg, LevelInfo, v...)
}

// Warn level message.
func Warn(t Tag, msg string, v ...any) {
	defaultLogger.log(t, msg, LevelWarn, v...)
}

// Error level message.
func Error(t Tag, msg string, v ...any) {
	defaultLogger.log(t, msg, LevelError, v...)
}

// Fatal level message, followed by an exit.
func Fatal(t Tag, msg string, v ...any) {
	defaultLogger.log(t, msg, LevelFatal, v...)
}
