package integration

import (
	"io"
)

type nativePacingWriteHook struct {
	writer  io.Writer
	hook    func() error
	called  bool
	callErr error
}

func (w *nativePacingWriteHook) Write(p []byte) (int, error) {
	if !w.called {
		w.called = true
		w.callErr = w.hook()
	}
	if w.callErr != nil {
		return 0, w.callErr
	}
	return w.writer.Write(p)
}
