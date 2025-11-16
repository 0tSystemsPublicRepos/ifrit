package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
)

type LogRotator struct {
	logDir   string
	rotation *config.LogRotationConfig
}

func NewLogRotator(logDir string, rotation *config.LogRotationConfig) *LogRotator {
	return &LogRotator{
		logDir:   logDir,
		rotation: rotation,
	}
}

// compressFile compresses a file to .gz and deletes the original
func (lr *LogRotator) compressFile(filePath string) error {
	inputFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputPath := filePath + ".gz"
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	gzWriter := gzip.NewWriter(outputFile)
	defer gzWriter.Close()

	if _, err := io.Copy(gzWriter, inputFile); err != nil {
		return err
	}

	// Delete original file after successful compression
	if err := os.Remove(filePath); err != nil {
		return err
	}

	fmt.Printf("[LOGGING] Compressed and archived: %s\n", filepath.Base(outputPath))
	return nil
}

// cleanup removes old log files based on age and count
func (lr *LogRotator) cleanup() error {
	files, err := os.ReadDir(lr.logDir)
	if err != nil {
		return err
	}

	now := time.Now()
	var logFiles []struct {
		name    string
		modTime time.Time
		path    string
	}

	// Collect all rotated log files (both .log and .log.gz)
	// Skip the current active log file (ifrit.log)
	for _, f := range files {
		if isRotatedLog(f.Name()) {
			info, err := f.Info()
			if err == nil {
				logFiles = append(logFiles, struct {
					name    string
					modTime time.Time
					path    string
				}{
					name:    f.Name(),
					modTime: info.ModTime(),
					path:    filepath.Join(lr.logDir, f.Name()),
				})
			}
		}
	}

	if len(logFiles) == 0 {
		return nil
	}

	// Sort by modification time (newest first)
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].modTime.After(logFiles[j].modTime)
	})

	deleteCount := 0

	// Remove files exceeding max_backups
	if len(logFiles) > lr.rotation.MaxBackups {
		for i := lr.rotation.MaxBackups; i < len(logFiles); i++ {
			if err := os.Remove(logFiles[i].path); err != nil {
				fmt.Printf("[WARNING] Failed to delete: %s - %v\n", logFiles[i].name, err)
			} else {
				fmt.Printf("[CLEANUP] Deleted old log (backup limit): %s\n", logFiles[i].name)
				deleteCount++
			}
		}
	}

	// Remove files older than max_age_days
	for _, file := range logFiles {
		age := now.Sub(file.modTime).Hours() / 24
		if int(age) > lr.rotation.MaxAgeDays {
			if err := os.Remove(file.path); err != nil {
				fmt.Printf("[WARNING] Failed to delete: %s - %v\n", file.name, err)
			} else {
				fmt.Printf("[CLEANUP] Deleted old log (age: %.0f days): %s\n", age, file.name)
				deleteCount++
			}
		}
	}

	if deleteCount > 0 {
		fmt.Printf("[LOGGING] Cleanup complete: removed %d old log files\n", deleteCount)
	}

	return nil
}

// isRotatedLog checks if a file is a rotated log file
// Current active log: ifrit.log
// Rotated logs: ifrit-2025-01-15T14-30-45.log or ifrit-2025-01-15T14-30-45.log.gz
func isRotatedLog(filename string) bool {
	// Skip the current active log file
	if filename == "ifrit.log" {
		return false
	}

	// Check if it's a compressed log
	if strings.HasSuffix(filename, ".log.gz") {
		return strings.HasPrefix(filename, "ifrit-")
	}

	// Check if it's an uncompressed rotated log
	if strings.HasSuffix(filename, ".log") {
		// Must start with "ifrit-" and contain a timestamp (indicated by 'T')
		return strings.HasPrefix(filename, "ifrit-") && strings.Contains(filename, "T")
	}

	return false
}
