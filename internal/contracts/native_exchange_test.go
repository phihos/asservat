package contracts

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNativeFrameBoundedBeforePayload(t *testing.T) {
	for _, test := range []struct {
		name string
		kind NativeFrameKind
		size uint32
	}{
		{"unknown", 99, 1}, {"empty", NativeDataFrame, 0}, {"control", NativeHelloFrame, NativeControlBytes + 1}, {"metadata", NativeMetadataFrame, NativeControlBytes + 1}, {"acknowledgement", NativeAcknowledgeFrame, NativeControlBytes + 1}, {"commit", NativeCommitFrame, NativeControlBytes + 1}, {"done", NativeDoneFrame, NativeControlBytes + 1}, {"command", NativeCommandFrame, NativeCommandBytes + 1}, {"payload", NativeDataFrame, NativeDataBytes + 1}, {"overflow", NativeDataFrame, 1 << 31},
	} {
		t.Run(test.name, func(t *testing.T) {
			var head [5]byte
			head[0] = byte(test.kind)
			binary.BigEndian.PutUint32(head[1:], test.size)
			if _, err := ReadNativeFrame(bytes.NewReader(head[:])); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
	for _, kind := range []NativeFrameKind{NativeHelloFrame, NativeDataFrame, NativeDoneFrame} {
		input := bytes.Repeat([]byte{37}, nativeFrameLimit(kind))
		var wire bytes.Buffer
		if err := WriteNativeFrame(&wire, NativeFrame{kind, input}); err != nil {
			t.Fatal(err)
		}
		got, err := ReadNativeFrame(&wire)
		if err != nil || got.Kind != kind || !bytes.Equal(got.Payload, input) {
			t.Fatal("bounded frame changed")
		}
		clear(got.Payload)
	}
}
func TestNativeControlClosedDecoder(t *testing.T) {
	valid := `{"format":"asservat-context-native/v1","reference":{"installationID":"a","sessionID":"b","workerID":"c","operationID":"d","fence":1},"nonce":"e","workerToken":null,"workerLeaf":null}`
	if _, err := DecodeNativeHello([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{valid + ` {}`, valid[:len(valid)-1] + `,"unexpected":true}`, valid[:len(valid)-1] + `,"nonce":"other"}`, `null`} {
		if _, err := DecodeNativeHello([]byte(raw)); err == nil {
			t.Fatal("ambiguous control accepted")
		}
	}
}
