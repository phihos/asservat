package contracts

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
)

var ErrKeyRPC = errors.New("invalid key protocol message")

// Closed wire decoding only; scope/authority and operation rules belong to the
// domain/application. Never log the rejected input or JSON decoder's error.
func decodeKeyRPC[T any](source io.Reader) (T, error) {
	return decodeClosedRPC[T](source, KeyServiceMaxBody)
}

func decodeClosedRPC[T any](source io.Reader, limit int64) (T, error) {
	var out T
	if source == nil {
		return out, ErrKeyRPC
	}
	b, err := io.ReadAll(io.LimitReader(source, limit+1))
	defer clear(b)
	if err != nil || len(b) == 0 || int64(len(b)) > limit || !jsontext.Value(b).IsValid() {
		return out, ErrKeyRPC
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, ErrKeyRPC
	}
	normal, err := json.Marshal(out)
	defer clear(normal)
	actual, expected := jsontext.Value(b), jsontext.Value(normal)
	if err != nil || actual.Canonicalize() != nil || expected.Canonicalize() != nil || !bytes.Equal(actual, expected) {
		return out, ErrKeyRPC
	}
	return out, nil
}

func DecodeKeyRequest(r io.Reader) (KeyServiceRequest, error) {
	return decodeKeyRPC[KeyServiceRequest](r)
}
func DecodeKeyResponse(r io.Reader) (KeyServiceResponse, error) {
	return decodeKeyRPC[KeyServiceResponse](r)
}
