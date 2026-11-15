package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

// UploadProfileStream sends one bounded native result once. A lost response
// cannot replay the acquisition or refill its node reservation.
func (c *Client) UploadProfileStream(ctx context.Context, r collector.ProfileResult, native io.Reader) error {
	if !r.Valid() || native == nil {
		return ErrRefused
	}
	head, err := json.Marshal(WireProfileResult(r))
	if err != nil || len(head) > contracts.NodeCaptureMaxHeader {
		return ErrRefused
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(head)))
	return c.send(ctx, contracts.NodeProfileCapturePath, contracts.NodeProfileCaptureContentType, int64(4+len(head))+r.Outcome.NativeBytes,
		io.MultiReader(bytes.NewReader(size[:]), bytes.NewReader(head), io.LimitReader(native, r.Outcome.NativeBytes)))
}

func (h *Handler) profile(w http.ResponseWriter, r *http.Request) {
	peer, err := h.peer(r)
	if err != nil {
		fail(w, err)
		return
	}
	if r.Header.Get("Content-Type") != contracts.NodeProfileCaptureContentType || r.ContentLength < 4 || r.ContentLength > 4+contracts.NodeCaptureMaxHeader+artifact.MaxGoTraceBytes {
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
	if err := h.channel.DeliverProfile(r.Context(), peer, result, body); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
