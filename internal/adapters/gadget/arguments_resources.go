package gadget

// ArgumentWorkingSet is an admission allowance, not a claimed Go/kernel heap
// measurement. Perf includes its metadata page. Map/decoder headroom covers the
// fixed two kernel thread tables, decoder halves and pairing states; physical
// collector limits and native qualification remain independent requirements.
func ArgumentWorkingSet(possibleCPUs, pageSize, maxTracked int) (int64, error) {
	if possibleCPUs < 1 || possibleCPUs > 256 || pageSize < 4096 || pageSize > 65536 || pageSize&(pageSize-1) != 0 || maxTracked < 1 || maxTracked > 16384 {
		return 0, ErrArgumentRequest
	}
	return int64(possibleCPUs)*9*int64(pageSize) + 2<<20 + int64(maxTracked)*4096, nil
}
