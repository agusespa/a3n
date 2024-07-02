package mocks

import (
	"log"
	"os"
)

type MockLogger struct {
	DevMode        bool
	LogDir         string
	CurrentLogFile *os.File
	FileLog        *log.Logger
}

func NewMockLogger(devMode bool) *MockLogger {
	return &MockLogger{
		DevMode:        devMode,
		LogDir:         "",
		CurrentLogFile: nil,
		FileLog:        log.New(os.Stdout, "", 0),
	}
}

func (l *MockLogger) LogFatal(err error) {
}

func (l *MockLogger) LogError(err error) {
}

func (l *MockLogger) LogWarn(message string) {
}

func (l *MockLogger) LogInfo(message string) {
}

func (l *MockLogger) LogDebug(message string) {
}
