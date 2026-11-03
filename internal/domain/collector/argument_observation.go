package collector

import "crypto/sha256"

// ArgumentObservationAccountingRule pins pre-read syscall accounting. Each
// eligible entry/exit consumes one event, 256 fixed bytes and 256 bytes for each
// eligible memory argument, even for a short or failed read. The engine applies
// an integer GCRA rate with a one-second burst before cumulative credit debit;
// it stops on rate/budget refusal or eight failed compare-and-swap attempts.
// Max-probe is derived from the pinned ABI definitions, not caller-selected.
// This digest is a contract identifier, never observation authority.
func ArgumentObservationAccountingRule() [32]byte {
	return sha256.Sum256([]byte("syscall-probe-v1;fixed=256;argument-reserve=256;entry-exit;rate=gcra-ceil-ns;burst=rate;overflow=stop;cas=8;no-refund;effective-rate=min(events,bytes/max-probe)"))
}
