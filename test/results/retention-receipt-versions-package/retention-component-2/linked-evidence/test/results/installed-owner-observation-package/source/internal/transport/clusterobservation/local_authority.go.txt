package clusterobservation

// Authority lets the fixed native listener require both observation handlers
// to use the same independently installed actual SNI and HTTP authority. It
// neither enables the route nor supplies current caller or backend authority.
func (h *LocalHandler) Authority() string {
	if h == nil {
		return ""
	}
	return h.host
}
