package capacity

// CapacityValues are the Helm `capacity` values in bytes as SQL applies them
// (capacity_apply; specs/capacity.md). Zero share or namespace limit means
// the default: usable bytes divided by max(8, enrolled workloads), and no
// namespace cap.
type CapacityValues struct {
	EvidenceBytes, ReserveBytes, ShareBytes, LimitBytes, NamespaceLimitBytes int64
	MaxConcurrentExpensive                                                   int64
	OnFull                                                                   string
}

// SettingsValid reports whether SQL can apply the values.
func (v CapacityValues) SettingsValid() bool {
	return v.EvidenceBytes > 0 && v.ReserveBytes >= 0 && v.ReserveBytes < v.EvidenceBytes && v.ShareBytes >= 0 && v.ShareBytes <= v.EvidenceBytes-v.ReserveBytes &&
		v.LimitBytes > 0 && v.ShareBytes <= v.LimitBytes && v.NamespaceLimitBytes >= 0 && v.MaxConcurrentExpensive > 0 && (v.OnFull == "RejectNewExpensive" || v.OnFull == "DeleteOldestEligibleInAccount")
}
