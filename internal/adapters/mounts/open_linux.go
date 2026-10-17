//go:build linux

package mounts

import (
	"golang.org/x/sys/unix"
	"os"
)

func open(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
