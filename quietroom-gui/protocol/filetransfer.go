package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"hash"
)

const (
	chunkSize   = 3900
	maxFileSize = 100 * 1024 * 1024 // 100MB
)

// FileTransferProgress is sent to the app layer during a transfer
type FileTransferProgress struct {
	Filename    string
	BytesSent   int64
	TotalBytes  int64
	Percent     float64
	Done        bool
	Error       string
	Hash        string
}

// FileReceiveState tracks an in-progress incoming file transfer
type FileReceiveState struct {
	Filename     string
	Filesize     int64
	ExpectedHash string
	OutFile      *os.File
	ReceivedSize int64
	Hash         hash.Hash
	DownloadPath string
}

// NewFileReceiveState initialises a receive state and creates the output file
func NewFileReceiveState(payload FileStartPayload, downloadDir string) (*FileReceiveState, error) {
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create download directory: %w", err)
	}

	filename := filepath.Base(payload.Filename)
	downloadPath := filepath.Join(downloadDir, filename)

	// Handle existing files by appending a counter
	if _, err := os.Stat(downloadPath); err == nil {
		ext := filepath.Ext(filename)
		name := strings.TrimSuffix(filename, ext)
		for i := 1; ; i++ {
			downloadPath = filepath.Join(downloadDir, fmt.Sprintf("%s_%d%s", name, i, ext))
			if _, err := os.Stat(downloadPath); os.IsNotExist(err) {
				break
			}
		}
	}

	outFile, err := os.Create(downloadPath)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file: %w", err)
	}

	return &FileReceiveState{
		Filename:     filename,
		Filesize:     payload.Filesize,
		ExpectedHash: payload.ExpectedHash,
		OutFile:      outFile,
		Hash: 		  sha256.New(),
		DownloadPath: downloadPath,
	}, nil
}

// Write processes a received file chunk
func (s *FileReceiveState) Write(data []byte) error {
	if _, err := s.OutFile.Write(data); err != nil {
		return err
	}
	s.Hash.Write(data)
	s.ReceivedSize += int64(len(data))
	return nil
}

// Finish closes the file and returns the hash verification result
func (s *FileReceiveState) Finish() (actualHash string, hashMatch bool, err error) {
	if s.OutFile != nil {
		s.OutFile.Close()
	}
	actualHash = hex.EncodeToString(s.Hash.Sum(nil))
	if s.ExpectedHash != "" {
		hashMatch = actualHash == s.ExpectedHash
	} else {
		hashMatch = true // no expected hash, treat as ok
	}
	return
}

// ComputeFileHash computes the SHA-256 hash of a file
func ComputeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SendFile sends a file to the server, reporting progress via the callback
func (c *Client) SendFile(filePath string, onProgress func(FileTransferProgress)) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("cannot send a directory")
	}
	if info.Size() > maxFileSize {
		return fmt.Errorf("file too large (max 100MB, file is %.2fMB)", float64(info.Size())/1024/1024)
	}

	fileHash, err := ComputeFileHash(filePath)
	if err != nil {
		return fmt.Errorf("cannot compute file hash: %w", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	filename := filepath.Base(filePath)
	filesize := info.Size()

	// Send FILE_START metadata
	metadata := fmt.Sprintf("FILE_START|%s|%s", filename, strconv.FormatInt(filesize, 10))
	encrypted, err := c.encrypt([]byte(metadata))
	if err != nil {
		return err
	}
	pkt := c.makePacket(PktFile, encrypted)
	c.sendMu.Lock()
	_, writeErr := c.conn.Write(pkt)
	c.sendMu.Unlock()
	if writeErr != nil {
		return fmt.Errorf("network error sending FILE_START: %w", writeErr)
	}

	time.Sleep(100 * time.Millisecond)

	buf := make([]byte, chunkSize)
	var totalSent int64

	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			encrypted, err := c.encrypt(chunk)
			if err != nil {
				return fmt.Errorf("encryption error during transfer: %w", err)
			}
			pkt := c.makePacket(PktFile, encrypted)
			c.sendMu.Lock()
			_, writeErr := c.conn.Write(pkt)
			c.sendMu.Unlock()
			if writeErr != nil {
				return fmt.Errorf("network error during transfer: %w", writeErr)
			}

			time.Sleep(30 * time.Millisecond)

			totalSent += int64(n)
			if onProgress != nil {
				onProgress(FileTransferProgress{
					Filename:   filename,
					BytesSent:  totalSent,
					TotalBytes: filesize,
					Percent:    float64(totalSent) / float64(filesize) * 100,
				})
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading file: %w", readErr)
		}
	}

	time.Sleep(100 * time.Millisecond)

	// Send FILE_END
	endEncrypted, err := c.encrypt([]byte("FILE_END"))
	if err != nil {
		return err
	}
	endPkt := c.makePacket(PktFile, endEncrypted)
	c.sendMu.Lock()
	_, writeErr = c.conn.Write(endPkt)
	c.sendMu.Unlock()
	if writeErr != nil {
		return fmt.Errorf("network error sending FILE_END: %w", writeErr)
	}

	if onProgress != nil {
		onProgress(FileTransferProgress{
			Filename:   filename,
			BytesSent:  totalSent,
			TotalBytes: filesize,
			Percent:    100,
			Done:       true,
			Hash:       fileHash,
		})
	}

	return nil
}
