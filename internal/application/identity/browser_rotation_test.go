package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

func TestBrowserReadOnlyResolveRecognizesCommittedCredentialReplacement(t *testing.T) {
	for _, oldDenied := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-token-valid", true: "old-token-denied"}[oldDenied], func(t *testing.T) {
			_, store, service, cookie := handoffFixture(t)
			if oldDenied {
				service.Identities = requestResolver(func(context.Context, string) (value.Identity, error) { return value.Identity{}, value.ErrDenied })
			}
			store.onRead = func(n int) {
				if n == 2 {
					store.record.Version++
				}
			}
			view, err := service.Resolve(context.Background(), cookie, false)
			if !errors.Is(err, value.ErrSessionBusy) || view.Identity.Principal.Valid() || store.reads != 2 {
				t.Fatal("committed same-session refresh became terminal or returned old identity", err, store.reads)
			}
		})
	}
}

func TestBrowserReadOnlyReplacementDoesNotMaskRealDenial(t *testing.T) {
	for _, mode := range []string{"unchanged", "decreased", "session-id", "principal", "provider-session", "created-at", "authenticated-at", "expiry-extension", "settings-revision", "expired", "original-observation-expired", "cancelled", "identity-contradiction"} {
		t.Run(mode, func(t *testing.T) {
			now, store, service, cookie := handoffFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service.Identities = requestResolver(func(context.Context, string) (value.Identity, error) { return value.Identity{}, value.ErrDenied })
			if mode == "identity-contradiction" {
				i := requestIdentity(*now)
				i.Principal = store.record.Principal
				i.Principal.Subject = "different-token-subject"
				service.Identities = handoffIdentity{i}
			}
			store.onRead = func(n int) {
				if n != 2 {
					return
				}
				store.record.Version++
				switch mode {
				case "unchanged":
					store.record.Version--
				case "decreased":
					store.record.Version = 0
				case "session-id":
					store.record.ID[0]++
				case "principal":
					store.record.Principal.Subject = "replacement"
				case "provider-session":
					store.record.ProviderSession = "replacement"
				case "created-at":
					store.record.CreatedAt = store.record.CreatedAt.Add(time.Millisecond)
				case "authenticated-at":
					store.record.AuthenticatedAt = store.record.AuthenticatedAt.Add(time.Millisecond)
				case "expiry-extension":
					store.record.ExpiresAt = store.record.ExpiresAt.Add(time.Second)
				case "settings-revision":
					store.record.Observation.Settings.Generation++
				case "expired":
					*now = now.Add(3 * time.Second)
				case "original-observation-expired":
					*now = now.Add(3 * time.Second)
					store.record.ExpiresAt = now.Add(time.Minute)
					store.record.Observation.ObservedAt = *now
					store.record.Observation.FreshUntil = now.Add(time.Second)
				case "cancelled":
					cancel()
				}
			}
			view, err := service.Resolve(ctx, cookie, false)
			if !errors.Is(err, value.ErrDenied) || view.Identity.Principal.Valid() {
				t.Fatal("replacement concealed denial", err)
			}
		})
	}
}

func TestLiveReaderKnownDenialCannotReviveSameGET(t *testing.T) {
	for _, mode := range []string{"new-batch", "current-batch"} {
		t.Run(mode, func(t *testing.T) {
			c := newLiveClock()
			denied := false
			calls := 0
			resolver := requestResolver(func(context.Context, string) (value.Identity, error) {
				calls++
				if denied {
					return value.Identity{}, value.ErrDenied
				}
				return requestIdentity(c.now()), nil
			})
			r, err := NewBearerLiveReader(t.Context(), resolver, "token", requestIdentity(c.now()).Principal, c.now().Add(time.Hour), c.now)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var batch IdentityBatch
			if mode == "current-batch" {
				batch, err = r.BeginBatch(t.Context())
				if err != nil {
					t.Fatal(err)
				}
			}
			denied = true
			if batch != nil {
				_, err = batch.ResolveIdentity(context.Background())
				batch.Close()
			} else {
				_, err = r.BeginBatch(t.Context())
			}
			if !errors.Is(err, value.ErrDenied) {
				t.Fatal("source denial was lost", err)
			}
			denied = false
			before := calls
			if _, err = r.BeginBatch(context.Background()); !errors.Is(err, value.ErrDenied) || calls != before {
				t.Fatal("newly permissive identity revived old GET", err, calls, before)
			}
		})
	}
}
