package fleet

// OwnerAuditEpochCapacity is the declared aggregate reservation required by one
// original policy. This is arithmetic, not measured physical backing or a grant.
// Bytes cover all known and uncertain ciphertext copies within the fixed
// per-epoch ceiling. Provider allocation overhead and residual backup/WAL
// capacity must be independently qualified by the protected provisioner.
type OwnerAuditEpochCapacity struct {
	Epochs, Dependencies int64
	Objects              OwnerAuditEpochBudget
}

func (p OwnerAuditEpochPolicy) RequiredCapacity() (OwnerAuditEpochCapacity, bool) {
	if !p.WellFormed() {
		return OwnerAuditEpochCapacity{}, false
	}
	n := p.MaxOpenEpochs
	return OwnerAuditEpochCapacity{
		Epochs:       n,
		Dependencies: n * p.MaxDependenciesPerEpoch,
		Objects: OwnerAuditEpochBudget{
			CiphertextBytes:  n * p.PerEpoch.CiphertextBytes,
			DataVersions:     n * p.PerEpoch.DataVersions,
			DeleteMarkers:    n * p.PerEpoch.DeleteMarkers,
			MultipartUploads: n * p.PerEpoch.MultipartUploads,
			MultipartParts:   n * p.PerEpoch.MultipartParts,
			MetadataBytes:    n * p.PerEpoch.MetadataBytes,
		},
	}, true
}

// OwnerAuditEpochSpend is a current accounting observation, never caller-supplied
// capacity authority. Each unresolved claim reserves its complete epoch budget
// before provider I/O and keeps that budget through uncertain outcome and
// physical retirement. Known is the observed aggregate, which may exceed the
// admitted bound; out-of-contract copies remain visible and stop new claims.
// Completed dependencies do not reduce either count until their concrete owner
// positively completes the original retained obligations.
type OwnerAuditEpochSpend struct {
	ChargedEpochs, PendingEpochs, UncertainEpochs, Dependencies int64
	Known                                                       OwnerAuditEpochBudget
}

// FitsAnotherEpoch checks only arithmetic room for a new full claim. Concrete
// SQL must separately verify current recovery/source, original reserve backing,
// cadence, one-use attempt and complete current known/uncertain accounting. This
// method cannot release charge, settle a writer, renew an epoch or select it.
func (s OwnerAuditEpochSpend) FitsAnotherEpoch(p OwnerAuditEpochPolicy) bool {
	capacity, ok := p.RequiredCapacity()
	if !ok || s.ChargedEpochs < 0 || s.ChargedEpochs >= capacity.Epochs || s.PendingEpochs != 0 || s.UncertainEpochs < 0 || s.UncertainEpochs > s.ChargedEpochs || s.UncertainEpochs >= p.MaxUncertainEpochs || s.Dependencies < 0 || s.Dependencies > s.ChargedEpochs*p.MaxDependenciesPerEpoch {
		return false
	}
	used := []int64{s.Known.CiphertextBytes, s.Known.DataVersions, s.Known.DeleteMarkers, s.Known.MultipartUploads, s.Known.MultipartParts, s.Known.MetadataBytes}
	per := []int64{p.PerEpoch.CiphertextBytes, p.PerEpoch.DataVersions, p.PerEpoch.DeleteMarkers, p.PerEpoch.MultipartUploads, p.PerEpoch.MultipartParts, p.PerEpoch.MetadataBytes}
	for i, n := range used {
		// Positive policy maxima and charged count were checked before this
		// multiplication. An empty inventory never subtracts unknown spend.
		if n < 0 || n > s.ChargedEpochs*per[i] {
			return false
		}
	}
	return true
}
