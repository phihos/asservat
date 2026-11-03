package collector

// ArgumentObservationAccountingRule pins pre-read syscall accounting. Each
// eligible entry/exit consumes one event, 256 fixed bytes and 256 bytes for each
// eligible memory argument, even for a short or failed read. The engine applies
// an integer GCRA rate with a one-second burst before cumulative credit debit;
// it stops on rate/budget refusal or eight failed compare-and-swap attempts.
// Max-probe is derived from the pinned ABI definitions, not caller-selected.
// This digest is a contract identifier, never observation authority.
func ArgumentObservationAccountingRule() [32]byte {
	return [32]byte{0x83, 0x3b, 0xaf, 0xd0, 0x11, 0x22, 0xa0, 0x99, 0xb6, 0xa4, 0x17, 0x51, 0xe9, 0xc5, 0x45, 0xdc, 0xcd, 0x92, 0x5d, 0x54, 0xf9, 0x4f, 0xaa, 0xbd, 0xfb, 0xa9, 0xf8, 0xf9, 0xbc, 0xd7, 0xee, 0xf6}
}
