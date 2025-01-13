/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package core

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/named-data/ndnd/std/log"
)

var shouldPrintTraceLogs = false
var logLevel log.Level
var logFileObj *os.File

// InitializeLogger initializes the logger.
func InitializeLogger(logFile string) {
	if logFile == "" {
		log.SetHandler(log.NewText(os.Stdout))
	} else {
		var err error
		logFileObj, err = os.Create(logFile)
		if err != nil {
			os.Exit(1)
		}
		log.SetHandler(log.NewText(logFileObj))
	}

	logLevelString := GetConfig().Core.LogLevel

	var err error
	logLevel, err = log.ParseLevel(logLevelString)
	if err == nil {
		log.SetLevel(logLevel)
	} else if logLevelString == "TRACE" {
		// Apex doesn't support the TRACE level, so we have to work around that by calling them DEBUG,
		// but not printing them if not TRACE
		log.SetLevel(log.DebugLevel)
		shouldPrintTraceLogs = true
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

// ShutdownLogger shuts down the logger.
func ShutdownLogger() {
	if logFileObj != nil {
		logFileObj.Close()
	}
}

func generateLogMessage(module interface{}, components ...interface{}) string {
	var message strings.Builder
	message.WriteString(fmt.Sprintf("[%v] ", module))
	for _, component := range components {
		switch v := component.(type) {
		case string:
			message.WriteString(v)
		case int:
			message.WriteString(strconv.Itoa(v))
		case int8:
			message.WriteString(strconv.FormatInt(int64(v), 10))
		case int16:
			message.WriteString(strconv.FormatInt(int64(v), 10))
		case int32:
			message.WriteString(strconv.FormatInt(int64(v), 10))
		case int64:
			message.WriteString(strconv.FormatInt(v, 10))
		case uint:
			message.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint8:
			message.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint16:
			message.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint32:
			message.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint64:
			message.WriteString(strconv.FormatUint(v, 10))
		case uintptr:
			message.WriteString(strconv.FormatUint(uint64(v), 10))
		case bool:
			message.WriteString(strconv.FormatBool(v))
		case error:
			message.WriteString(v.Error())
		default:
			message.WriteString(fmt.Sprintf("%v", component))
		}
	}
	return message.String()
}

// LogFatal logs a message at the FATAL level. Note: Fatal will let the program exit
func LogFatal(module interface{}, components ...interface{}) {
	if logLevel <= log.FatalLevel {
		log.Fatal(generateLogMessage(module, components...))
	}
}

// LogError logs a message at the ERROR level.
func LogError(module interface{}, components ...interface{}) {
	if logLevel <= log.ErrorLevel {
		log.Error(generateLogMessage(module, components...))
	}
}

// LogWarn logs a message at the WARN level.
func LogWarn(module interface{}, components ...interface{}) {
	if logLevel <= log.WarnLevel {
		log.Warn(generateLogMessage(module, components...))
	}
}

// LogInfo logs a message at the INFO level.
func LogInfo(module interface{}, components ...interface{}) {
	if logLevel <= log.InfoLevel {
		log.Info(generateLogMessage(module, components...))
	}
}

// LogDebug logs a message at the DEBUG level.
func LogDebug(module interface{}, components ...interface{}) {
	if logLevel <= log.DebugLevel {
		log.Debug(generateLogMessage(module, components...))
	}
}

// LogTrace logs a message at the TRACE level (really just additional DEBUG messages).
func LogTrace(module interface{}, components ...interface{}) {
	if shouldPrintTraceLogs {
		log.Debug(generateLogMessage(module, components...))
	}
}

func HasTraceLogs() bool {
	return shouldPrintTraceLogs
}

func HasDebugLogs() bool {
	return logLevel <= log.DebugLevel
}
