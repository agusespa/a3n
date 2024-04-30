package logger

import (
	"log"
)

type Logger struct {
	DevMode bool
}

func NewLogger(devMode bool) *Logger {
	if devMode {
		log.Println("INFO running in development mode")
	}
	return &Logger{DevMode: devMode}
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
	if l.DevMode {
		log.Printf("DEBUG %s", message)
	}
}
