package logger

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Logger struct {
	DevMode        bool
	CurrentLogFile *os.File
	FileLog        *log.Logger
}

func NewLogger(devMode bool) *Logger {
	if devMode {
		log.Println("INFO running in development mode")
	}

	var fileLogger *log.Logger
	logFile, err := getUserLogFile()
	if err != nil {
		message := fmt.Sprintf("FATAL error getting log file %s", err.Error())
		log.Fatal(message)
	} else {
		fileLogger = log.New(logFile, "", log.LstdFlags)
	}

	return &Logger{DevMode: devMode, CurrentLogFile: logFile, FileLog: fileLogger}
}

func (l *Logger) LogFatal(err error) {
	message := fmt.Sprintf("FATAL %s", err.Error())
	l.LogToFile(message)
	log.Fatal(message)
}

func (l *Logger) LogError(err error) {
	message := fmt.Sprintf("ERROR %s", err.Error())
	log.Println(message)
	l.LogToFile(message)
}

func (l *Logger) LogWarn(message string) {
	message = fmt.Sprintf("WARNING %s", message)
	log.Println(message)
	l.LogToFile(message)
}

func (l *Logger) LogInfo(message string) {
	message = fmt.Sprintf("INFO %s", message)
	log.Println(message)
	l.LogToFile(message)
}

func (l *Logger) LogDebug(message string) {
	message = fmt.Sprintf("DEBUG %s", message)
	l.LogToFile(message)

	if l.DevMode {
		log.Println(message)
	}
}

func (l *Logger) LogToFile(message string) {
	err := l.refreshLogFile()
	if err != nil {
		message := fmt.Sprintf("FATAL error refreshing log file %s", err.Error())
		log.Fatal(message)
	}

	l.FileLog.Println(message)
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

	files, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	y, m, d := now.Date()
	date := fmt.Sprintf(`%d-%d-%d`, y, m, d)

	var filteredFiles []string

	for _, f := range files {
		filename := f.Name()
		if strings.HasPrefix(filename, date) {
			filteredFiles = append(filteredFiles, filename[:len(filename)-4])
		}
	}

	var logFileName string

	if len(filteredFiles) > 0 {
		logFileName = filteredFiles[0]
		for i := 1; i < len(filteredFiles); i++ {
			latestNum := strings.Split(logFileName, "_")[1]
			currentNum := strings.Split(filteredFiles[i], "_")[1]
			if currentNum > latestNum {
				logFileName = filteredFiles[i]
			}
		}
	} else {
		logFileName = fmt.Sprintf(`%s_1`, date)
	}

	logFileName = fmt.Sprintf(`%s.log`, logFileName)
	logFile, err := os.OpenFile(filepath.Join(logDir, logFileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	return logFile, nil
}

func (l *Logger) refreshLogFile() error {
	filenamepath := l.CurrentLogFile.Name()
	filename, path := getFilenameAndPath(filenamepath)

	now := time.Now()
	y, m, d := now.Date()
	date := fmt.Sprintf(`%d-%d-%d`, y, m, d)

	var newFileName string
	if !strings.HasPrefix(filename, date) {
		newFileName = fmt.Sprintf(`%s_1.log`, date)
	} else {
		info, err := l.CurrentLogFile.Stat()
		if err != nil {
			return err
		}

		if info.Size() < 10000000 {
			return nil
		}

		oldName := filename[:len(filename)-4]
		currNum := strings.Split(oldName, "_")[1]
		num, err := strconv.Atoi(currNum)
		if err != nil {
			return err
		}
		newFileName = fmt.Sprintf(`%s_%d.log`, date, num+1)
	}

	logFile, err := os.OpenFile(filepath.Join(path, newFileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	l.CurrentLogFile = logFile
	l.FileLog = log.New(logFile, "", log.LstdFlags)
	return nil
}

func getFilenameAndPath(path string) (string, string) {
	index := -1
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			index = i
		}
	}
	if index < 1 {
		return "", path
	}
	return path[index+1:], path[:index]
}
