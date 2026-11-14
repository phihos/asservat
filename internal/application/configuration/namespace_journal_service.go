package configuration

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

// NamespaceJournalIdle stops a connector's namespace journal no caller has
// read for this long (ADR-247).
const NamespaceJournalIdle = 2 * time.Minute

// NamespaceJournalSnapshot is one consistent journal state: its ID and
// sequence, the start of its latest LIST or clean watch session, and the
// namespaces with journal versions.
type NamespaceJournalSnapshot struct {
	Journal    string
	Sequence   int64
	ObservedAt time.Time
	Namespaces []value.ObservedNamespace
}

func newJournalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
