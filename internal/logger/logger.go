package logger

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
)

type Logger struct {
	DevMode bool
	FileLog *log.Logger
}

func NewLogger(devMode bool) *Logger {
	if devMode {
		log.Println("INFO running in development mode")
	}

	var fileLogger *log.Logger
	logFile, err := getUserLogFile()
	if err != nil {
		log.Printf("ERROR Failed getting log file: %s", err.Error())
		fileLogger = nil
	} else {
		fileLogger = log.New(logFile, "", log.LstdFlags)
	}

	return &Logger{DevMode: devMode, FileLog: fileLogger}
}

func (l *Logger) LogFatal(err error) {
	log.Fatalf("FATAL %s", err.Error())
}

func (l *Logger) LogError(err error) {
	log.Printf("ERROR %s", err.Error())
}

func (l *Logger) LogWarn(message string) {
	log.Printf("WARN %s", message)
}

func (l *Logger) LogInfo(message string) {
	log.Printf("INFO %s", message)
}

func (l *Logger) LogDebug(message string) {
	message = fmt.Sprintf("DEBUG %s", message)
	l.FileLog.Println(message)

	if l.DevMode {
		log.Println(message)
	}
}

func getUserLogFile() (*os.File, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}

	homeDir := currentUser.HomeDir
	logDir := filepath.Join(homeDir, ".a3n", "logs")
	if err = os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	logFile, err := os.OpenFile(filepath.Join(logDir, "auth.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	return logFile, nil
}
