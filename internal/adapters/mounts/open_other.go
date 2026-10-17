//go:build !linux

package mounts

import "os"

func open(*os.Root, string) (*os.File, error) { return nil, ErrUnavailable }
