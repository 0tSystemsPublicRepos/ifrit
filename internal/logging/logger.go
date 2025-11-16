package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelError
	LogLevelAttack
)

type Logger struct {
	mu        sync.Mutex
	file      *os.File
	logger    *log.Logger
	logDir    string
	logPath   string
	maxSize   int64
	rotator   *LogRotator
	level     LogLevel
	counter   int // Counter for same-day rotations
}

var defaultLogger *Logger

func Init(logDir string, rotation *config.LogRotationConfig, logLevel string, debug bool) error {
	// Create log directory
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// Parse log level
	level := parseLogLevel(logLevel, debug)

	// Create log rotator
	rotator := NewLogRotator(logDir, rotation)

	// Use simple sequential naming: ifrit.log, ifrit-1.log, ifrit-2.log, etc.
	logPath := filepath.Join(logDir, "ifrit.log")
	
	// Create or open the log file
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	maxSize := int64(rotation.MaxSizeMB) * 1024 * 1024

	// Use MultiWriter to write to both file and stdout
	multiWriter := io.MultiWriter(file, os.Stdout)

	logger := &Logger{
		file:    file,
		logger:  log.New(multiWriter, "", log.LstdFlags),
		logDir:  logDir,
		logPath: logPath,
		maxSize: maxSize,
		rotator: rotator,
		level:   level,
		counter: 0,
	}

	defaultLogger = logger
	
	// Redirect Go's standard log package to also write to our log file
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags)
	
	fmt.Printf("[LOGGING] Initialized - LogDir: %s, MaxSize: %d MB, Level: %s\n", 
		logDir, rotation.MaxSizeMB, logLevel)
	return nil
}

func parseLogLevel(level string, debug bool) LogLevel {
	if debug {
		return LogLevelDebug
	}
	
	switch strings.ToLower(level) {
	case "debug":
		return LogLevelDebug
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// writeLog handles the actual logging with rotation check
func (l *Logger) writeLog(level LogLevel, levelStr, msg string) {
	// Check log level
	if level < l.level {
		return // Don't log if below configured level
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if we need to rotate based on size
	fileInfo, err := os.Stat(l.logPath)
	if err == nil && fileInfo.Size() >= l.maxSize {
		// Rotate the log file
		if err := l.rotateFile(); err != nil {
			fmt.Printf("[WARNING] Failed to rotate log: %v\n", err)
		}
	}

	// Write the log entry
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	l.logger.Printf("[%s] [%s] %s", timestamp, levelStr, msg)
}

func (l *Logger) rotateFile() error {
	// Close current file
	if l.file != nil {
		l.file.Close()
	}

	// Generate rotated filename with counter
	l.counter++
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	rotatedPath := filepath.Join(l.logDir, fmt.Sprintf("ifrit-%s.log", timestamp))
	
	// Rename current log file
	if err := os.Rename(l.logPath, rotatedPath); err != nil {
		return fmt.Errorf("failed to rename log file: %w", err)
	}

	fileInfo, _ := os.Stat(rotatedPath)
	fileSizeMB := float64(fileInfo.Size()) / 1024 / 1024
	fmt.Printf("[LOGGING] Rotated log file (size: %.2f MB) -> %s\n", fileSizeMB, filepath.Base(rotatedPath))

	// Create new log file
	file, err := os.OpenFile(l.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}

	l.file = file
	multiWriter := io.MultiWriter(file, os.Stdout)
	l.logger = log.New(multiWriter, "", log.LstdFlags)

	// Compress the rotated file asynchronously
	go func(path string) {
		if err := l.rotator.compressFile(path); err != nil {
			fmt.Printf("[WARNING] Failed to compress log file: %v\n", err)
		}
		// Clean up old files after compression
		if err := l.rotator.cleanup(); err != nil {
			fmt.Printf("[WARNING] Failed to cleanup old logs: %v\n", err)
		}
	}(rotatedPath)

	return nil
}

func Info(msg string, args ...interface{}) {
	text := fmt.Sprintf(msg, args...)
	fmt.Printf("[INFO] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.writeLog(LogLevelInfo, "INFO", text)
	}
}

func Error(msg string, args ...interface{}) {
	text := fmt.Sprintf(msg, args...)
	fmt.Printf("[ERROR] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.writeLog(LogLevelError, "ERROR", text)
	}
}

func Debug(msg string, args ...interface{}) {
	text := fmt.Sprintf(msg, args...)
	fmt.Printf("[DEBUG] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.writeLog(LogLevelDebug, "DEBUG", text)
	}
}

func Attack(sourceIP, method, path, attackType, stage string) {
	text := fmt.Sprintf("ATTACK | IP: %s | %s %s | Type: %s | %s", sourceIP, method, path, attackType, stage)
	fmt.Printf("[ATTACK] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.writeLog(LogLevelAttack, "ATTACK", text)
	}
}

func Close() {
	if defaultLogger != nil && defaultLogger.file != nil {
		defaultLogger.mu.Lock()
		defer defaultLogger.mu.Unlock()
		defaultLogger.file.Close()
	}
}
