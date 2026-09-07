//go:build darwin || linux

package semantics

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxInspectedFile = 64 * 1024

// Read only a bounded, already-observed regular file. NOFOLLOW and NONBLOCK
// prevent a raced final symlink or FIFO from redirecting/blocking this read.
// Object identity is checked before reading; a hook still cannot make later
// execution atomic with this inspection.
func readBoundedFile(path string, expected os.FileInfo) ([]byte, error) {
	if expected == nil || !expected.Mode().IsRegular() || expected.Size() > maxInspectedFile {
		return nil, errors.New("file is outside bounded inspection")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !os.SameFile(expected, before) || !before.Mode().IsRegular() || before.Size() != expected.Size() || !before.ModTime().Equal(expected.ModTime()) {
		return nil, errors.New("file identity or content state changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxInspectedFile+1))
	if err != nil || len(data) > maxInspectedFile {
		return nil, errors.New("file read exceeded bounded inspection")
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("file changed during inspection")
	}
	return data, nil
}

func sharedFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink > 1
}

func trustedSystemFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0
}
