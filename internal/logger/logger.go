package logger

import (
	"log"
)

func LogFatal(message string) {
	log.Fatalf("FATAL ERROR %s", message)
}

func LogError(message string) {
	log.Printf("ERROR %s", message)
}

func LogInfo(message string) {
	log.Printf("INFO %s", message)
}
