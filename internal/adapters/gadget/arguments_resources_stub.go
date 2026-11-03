//go:build !gadget || !linux

package gadget

func ArgumentWorkingBytes(int) (int64, error) { return 0, ErrEngineUnavailable }
