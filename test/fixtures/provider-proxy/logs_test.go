//go:build ignore

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignalLogFixturePreservesInvalidEmptyAndLongBytes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := writeSignalLogFixture(&stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	want := append([]byte("synthetic-finite-logs-once\n\n\xff\x00\n"), bytes.Repeat([]byte{'L'}, 9000)...)
	want = append(want, '\n')
	if !bytes.Equal(stdout.Bytes(), want) || stderr.String() != "synthetic-finite-logs-stderr\n" {
		t.Fatal("synthetic source bytes changed")
	}
	fail := errors.New("synthetic output failure")
	if !errors.Is(writeSignalLogFixture(signalFailWriter{fail}, &stderr), fail) {
		t.Fatal("source write failure hidden")
	}
}

type signalFailWriter struct{ err error }

func (w signalFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestSignalExitRequiresOneExplicitPOST(t *testing.T) {
	stops := 0
	h := signalExit(func() { stops++ })
	get := httptest.NewRecorder()
	h(get, httptest.NewRequest(http.MethodGet, "/exit", nil))
	if get.Code != http.StatusMethodNotAllowed || stops != 0 {
		t.Fatal("read stopped synthetic process")
	}
	post := httptest.NewRecorder()
	h(post, httptest.NewRequest(http.MethodPost, "/exit", nil))
	if post.Code != http.StatusOK || stops != 1 || post.Body.String() != "synthetic signal process stopping\n" {
		t.Fatal("explicit exit request not acknowledged")
	}
}
