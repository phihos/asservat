package contracts

import (
	"encoding/json"
	"io"
	"time"
)

const LiveOwnerPath = "/internal/live-watch/v1/owner"
const LiveOwnerMedia = "application/vnd.asservat.live-watch-owner.v1"
const LiveOwnerFormat = "asservat-live-watch-owner/v1"
const LiveOwnerInputBytes = 16 << 10
const LiveOwnerResultBytes = 32 << 10

type LiveOwnerPolicy struct {
	UID        string
	Generation int64
	Digest     [32]byte
}

type LiveOwnerActor struct{ Issuer, Subject, ClientID, Kind string }

// Actor is a binding only, never an identity observation. The original ingress
// must answer actual current-identity callbacks on this same authenticated call.
type LiveOwnerHello struct {
	Format                         string
	RootID, OwnerID, CallID, Nonce string
	Until                          time.Time
	Actor                          LiveOwnerActor
	Command                        json.RawMessage
	Policy                         LiveOwnerPolicy
}

func DecodeLiveOwnerHello(r io.Reader) (LiveOwnerHello, error) {
	h, err := decodeClosedRPC[LiveOwnerHello](r, NativeControlBytes)
	if err != nil || h.Format != LiveOwnerFormat || !routingUUID(h.RootID) || !routingUUID(h.OwnerID) || !routingUUID(h.CallID) || !ValidWorkerNonce(h.Nonce) || h.Until.IsZero() || len(h.Command) == 0 || len(h.Command) > LiveOwnerInputBytes || h.Actor.Issuer == "" || h.Actor.Subject == "" || h.Actor.ClientID == "" || (h.Actor.Kind != "human" && h.Actor.Kind != "workload") {
		return LiveOwnerHello{}, ErrNativeProtocol
	}
	return h, nil
}

// A single sequential conversation: current→identity callbacks, then one
// result/error, retained until done. No bearer token, cookie or assertion exists.
type LiveOwnerFrame struct {
	Kind     string
	Nonce    string
	Sequence uint64
	Until    time.Time
	Identity json.RawMessage `json:",omitempty"`
	Result   json.RawMessage `json:",omitempty"`
	Failure  string          `json:",omitempty"`
}

func DecodeLiveOwnerFrame(r io.Reader) (LiveOwnerFrame, error) {
	f, err := decodeClosedRPC[LiveOwnerFrame](r, NativeCommandBytes)
	if err != nil || !ValidWorkerNonce(f.Nonce) || f.Sequence == 0 || f.Sequence > NativeMaximumFrames || f.Until.IsZero() {
		return LiveOwnerFrame{}, ErrNativeProtocol
	}
	switch f.Kind {
	case "current", "done":
		if len(f.Identity) != 0 || len(f.Result) != 0 || f.Failure != "" {
			return LiveOwnerFrame{}, ErrNativeProtocol
		}
	case "identity":
		if len(f.Identity) == 0 || len(f.Identity) > NativeCommandBytes-1024 || len(f.Result) != 0 || f.Failure != "" {
			return LiveOwnerFrame{}, ErrNativeProtocol
		}
	case "result":
		if len(f.Result) == 0 || len(f.Result) > LiveOwnerResultBytes || len(f.Identity) != 0 || f.Failure != "" {
			return LiveOwnerFrame{}, ErrNativeProtocol
		}
	case "error":
		if len(f.Result) != 0 || len(f.Identity) != 0 || (f.Failure != "denied" && f.Failure != "unavailable" && f.Failure != "conflict" && f.Failure != "capacity" && f.Failure != "invalid") {
			return LiveOwnerFrame{}, ErrNativeProtocol
		}
	default:
		return LiveOwnerFrame{}, ErrNativeProtocol
	}
	return f, nil
}
