package gadget

// completePrefix checks bytes actually supplied by the pinned engine; no packet
// parsing, padding or inference from retained output is involved.
func completePrefix(captured int, wire uint32, snaplen int) bool {
	if wire == 0 || snaplen <= 0 {
		return false
	}
	want := uint64(wire)
	if want > uint64(snaplen) {
		want = uint64(snaplen)
	}
	return captured >= 0 && uint64(captured) == want
}
