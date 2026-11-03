package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

// UploadProfile sends one bounded native result once. A lost response cannot
// replay the acquisition or refill its node reservation.
func (c *Client) UploadProfile(ctx context.Context, epoch string, r collector.ProfileResult, native []byte) error {
	if int64(len(native)) != r.Outcome.NativeBytes {
		return ErrRefused
	}
	return c.UploadProfileStream(ctx, epoch, r, bytes.NewReader(native))
}

func (c *Client) UploadProfileStream(ctx context.Context, epoch string, r collector.ProfileResult, native io.Reader) error {
	if !r.Valid() || native == nil {
		return ErrRefused
	}
	head, err := json.Marshal(WireProfileResult(epoch, r))
	if err != nil || len(head) > contracts.NodeCaptureMaxHeader {
		return ErrRefused
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(head)))
	body := io.MultiReader(bytes.NewReader(size[:]), bytes.NewReader(head), io.LimitReader(native, r.Outcome.NativeBytes))
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	u := *c.base
	u.Path = contracts.NodeProfileCapturePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return ErrRefused
	}
	req.ContentLength = int64(4+len(head)) + r.Outcome.NativeBytes
	req.Header.Set("Content-Type", contracts.NodeProfileCaptureContentType)
	response, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthenticated
	case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict:
		return ErrRefused
	}
	return ErrUnavailable
}

func (h *Handler) profile(w http.ResponseWriter, r *http.Request) {
	peer, err := h.peer(r)
	if err != nil {
		w.WriteHeader(status(err))
		return
	}
	if r.ContentLength < 4 || r.ContentLength > 4+contracts.NodeCaptureMaxHeader+artifact.MaxGoTraceBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body := http.MaxBytesReader(w, r.Body, r.ContentLength)
	var size [4]byte
	if _, err := io.ReadFull(body, size[:]); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > contracts.NodeCaptureMaxHeader {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	head, err := contracts.DecodeNodeProfileResult(io.LimitReader(body, int64(n)))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result, ok := DomainProfileResult(head)
	if !ok || r.ContentLength != 4+int64(n)+result.Outcome.NativeBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := h.channel.DeliverProfile(r.Context(), peer, head.Epoch, result, body); err != nil {
		w.WriteHeader(status(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
