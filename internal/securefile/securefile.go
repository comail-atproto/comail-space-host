// SPDX-License-Identifier: AGPL-3.0-or-later

// Package securefile reads bounded private files without following a final
// symlink. It also recognizes the exact file shape systemd exposes through
// LoadCredential to a DynamicUser service.
package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Read returns at most maxBytes from an absolute owner-only regular file.
// systemd LoadCredential files are accepted only when they are an exact 0440
// direct child of the manager-provided CREDENTIALS_DIRECTORY. systemd grants
// the service user access with an ACL; ordinary group-readable files remain
// rejected.
func Read(path string, maxBytes int64) ([]byte, error) {
	if !filepath.IsAbs(path) || path == string(filepath.Separator) {
		return nil, errors.New("securefile: path must be absolute")
	}
	if maxBytes <= 0 {
		return nil, errors.New("securefile: positive size bound is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !safe(path, info) {
		return nil, errors.New("securefile: file must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !safe(path, opened) || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("securefile: file changed or became unsafe while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("securefile: file exceeds size bound")
	}
	return data, nil
}

func safe(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	permissions := info.Mode().Perm()
	if permissions&0o177 == 0 {
		return true
	}
	credentialDirectory := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY"))
	if permissions != 0o440 || credentialDirectory == "" || !filepath.IsAbs(credentialDirectory) {
		return false
	}
	cleanDirectory := filepath.Clean(credentialDirectory)
	directoryInfo, err := os.Lstat(cleanDirectory)
	if err != nil || !directoryInfo.IsDir() {
		return false
	}
	cleanPath := filepath.Clean(path)
	return cleanPath != cleanDirectory && filepath.Dir(cleanPath) == cleanDirectory
}
