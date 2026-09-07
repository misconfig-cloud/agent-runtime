//go:build !darwin && !linux

package semantics

import (
	"errors"
	"os"
)

func readBoundedFile(string, os.FileInfo) ([]byte, error) {
	return nil, errors.New("bounded file inspection is unsupported on this platform")
}

func sharedFile(os.FileInfo) bool { return true }

func trustedSystemFile(os.FileInfo) bool { return false }
