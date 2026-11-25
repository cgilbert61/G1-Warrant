//go:build !linux

package envseal

import "fmt"

func platformSupportsReexec() bool {
	return false
}

func reexecSealed(_ []string, _ []byte) error {
	return nil
}

func readAndCloseFD(fd int) ([]byte, error) {
	return nil, fmt.Errorf("envseal pipe fd %d handoff is only supported on linux", fd)
}
