//go:build linux

package envseal

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
)

func platformSupportsReexec() bool {
	return true
}

// reexecSealed replaces the current process image with the same binary and a scrubbed
// environment block. The secret payload is written to a pipe whose read end survives
// syscall.Exec (no O_CLOEXEC) and is advertised via SealFDEnv. Only returns on error.
func reexecSealed(env []string, payload []byte) error {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], 0); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	rfd, wfd := fds[0], fds[1]
	if err := writeFully(wfd, payload); err != nil {
		_ = syscall.Close(rfd)
		_ = syscall.Close(wfd)
		return fmt.Errorf("handoff write: %w", err)
	}
	_ = syscall.Close(wfd)

	exe, err := os.Executable()
	if err != nil {
		_ = syscall.Close(rfd)
		return fmt.Errorf("locate executable: %w", err)
	}
	env = append(env, SealFDEnv+"="+strconv.Itoa(rfd))
	err = syscall.Exec(exe, os.Args, env)
	_ = syscall.Close(rfd)
	return fmt.Errorf("syscall.Exec: %w", err)
}

func writeFully(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := syscall.Write(fd, b)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		b = b[n:]
	}
	return nil
}

func readAndCloseFD(fd int) ([]byte, error) {
	f := os.NewFile(uintptr(fd), "warrant-envseal-pipe")
	if f == nil {
		return nil, fmt.Errorf("invalid fd %d", fd)
	}
	defer func() { _ = f.Close() }()
	const maxSealedPayload = 2 * 1024 * 1024 // 2 MiB hard cap
	data, err := io.ReadAll(io.LimitReader(f, maxSealedPayload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSealedPayload {
		return nil, fmt.Errorf("sealed payload exceeds %d byte cap", maxSealedPayload)
	}
	return data, nil
}
