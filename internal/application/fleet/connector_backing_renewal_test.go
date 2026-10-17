package fleet

import (
	"reflect"
	"testing"
	"time"
)

// These are pure compatibility/accounting checks. They do not establish source
// acceptance, measured backing, or preservation of persisted process/leaf dates;
// the SQL renewal qualification must cover those effects separately.
func connectorRenewalBacking(t *testing.T) ConnectorIdentityBacking {
	t.Helper()
	f, _ := connectorSourceConfiguration(t)
	b := f.cfg.Backing.Clone()
	// Include the retained root in addition to the two profile rows. The older
	// fixture's four MiB covered only profiles and must not pay for the root too.
	b.SourceBackupReservedBytes = 6 << 20
	if !b.Valid() {
		t.Fatal("invalid renewal fixture")
	}
	return b
}

func connectorRenewalPoolBacking(b *ConnectorIdentityBacking) {
	b.Policy.MetadataSlots = b.AccountLimit * b.RecordsPerAccount
	backup, wal := b.Policy.History.SlotBacking(b.Policy.MaxPurgeLeases)
	b.Policy.BackupReservedBytes = backup * b.Policy.MetadataSlots
	b.Policy.WALReservedBytes = wal * b.Policy.MetadataSlots
}

func TestConnectorBackingRenewalAllowsOnlyNextPolicyInterval(t *testing.T) {
	previous := connectorRenewalBacking(t)
	next := previous.Clone()
	next.Policy.BackingRevision++
	next.Policy.ValidUntil = next.Policy.ValidUntil.Add(time.Hour)
	if !next.CanRenew(previous) {
		t.Fatal("compatible next original policy interval denied")
	}
	next.Policy.PolicyID = "20000000-0000-4000-8000-000000000002"
	next.Policy.PolicyDigest[0]++
	if !next.CanRenew(previous) {
		t.Fatal("new exact policy identity denied with unchanged backing")
	}
	for _, tc := range []struct {
		name string
		edit func(*ConnectorIdentityBacking)
	}{
		{"same revision", func(b *ConnectorIdentityBacking) { b.Policy.BackingRevision = previous.Policy.BackingRevision }},
		{"skipped revision", func(b *ConnectorIdentityBacking) { b.Policy.BackingRevision += 1 }},
		{"zero revision", func(b *ConnectorIdentityBacking) { b.Policy.BackingRevision = 0 }},
		{"same deadline", func(b *ConnectorIdentityBacking) { b.Policy.ValidUntil = previous.Policy.ValidUntil }},
		{"shorter deadline", func(b *ConnectorIdentityBacking) {
			b.Policy.ValidUntil = previous.Policy.ValidUntil.Add(-time.Microsecond)
		}},
		{"missing deadline", func(b *ConnectorIdentityBacking) { b.Policy.ValidUntil = time.Time{} }},
		{"non SQL precision deadline", func(b *ConnectorIdentityBacking) { b.Policy.ValidUntil = b.Policy.ValidUntil.Add(time.Nanosecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := next.Clone()
			tc.edit(&candidate)
			if candidate.CanRenew(previous) {
				t.Fatal("invalid revision/deadline transition accepted")
			}
		})
	}
	priorSecond := previous.Clone()
	priorSecond.Policy.BackingRevision = 2
	rollback := previous.Clone()
	rollback.Policy.ValidUntil = priorSecond.Policy.ValidUntil.Add(time.Hour)
	if rollback.CanRenew(priorSecond) {
		t.Fatal("valid old revision revived by a later deadline")
	}
	maximum := previous.Clone()
	maximum.Policy.BackingRevision = 1 << 60
	overflow := maximum.Clone()
	overflow.Policy.BackingRevision++
	overflow.Policy.ValidUntil = maximum.Policy.ValidUntil.Add(time.Hour)
	if overflow.CanRenew(maximum) {
		t.Fatal("renewal exceeded the accepted revision range")
	}
}

func TestConnectorBackingRenewalDoesNotRefillOrChangeQualification(t *testing.T) {
	previous := connectorRenewalBacking(t)
	for _, tc := range []struct {
		name string
		edit func(*ConnectorIdentityBacking)
	}{
		{"account version", func(b *ConnectorIdentityBacking) { b.AccountVersion = "account-v2" }},
		{"account limit", func(b *ConnectorIdentityBacking) { b.AccountLimit++; connectorRenewalPoolBacking(b) }},
		{"records per account", func(b *ConnectorIdentityBacking) { b.RecordsPerAccount++; connectorRenewalPoolBacking(b) }},
		{"retention interval", func(b *ConnectorIdentityBacking) { b.RetainedSeconds++ }},
		{"profile limit", func(b *ConnectorIdentityBacking) { b.ProfileLimit-- }},
		{"source transitions", func(b *ConnectorIdentityBacking) {
			b.SourceTransitionLimit++
			q := b.Policy.History
			b.SourceWALReservedBytes = 2 * b.SourceTransitionLimit * q.MaximumTransitionWALBytes * q.WALCopies
		}},
		{"source backup increase", func(b *ConnectorIdentityBacking) { b.SourceBackupReservedBytes++ }},
		{"source WAL increase", func(b *ConnectorIdentityBacking) { b.SourceWALReservedBytes++ }},
		{"installation", func(b *ConnectorIdentityBacking) { b.Policy.InstallationID = "20000000-0000-4000-8000-000000000002" }},
		{"root", func(b *ConnectorIdentityBacking) { b.Policy.RootID = "20000000-0000-4000-8000-000000000002" }},
		{"store", func(b *ConnectorIdentityBacking) { b.Policy.StoreID = "20000000-0000-4000-8000-000000000002" }},
		{"backup profile", func(b *ConnectorIdentityBacking) { b.Policy.BackupProfileID = "20000000-0000-4000-8000-000000000002" }},
		{"backup profile digest", func(b *ConnectorIdentityBacking) { b.Policy.BackupProfileDigest[0]++ }},
		{"metadata slots", func(b *ConnectorIdentityBacking) {
			b.Policy.MetadataSlots++
			backup, wal := b.Policy.History.SlotBacking(b.Policy.MaxPurgeLeases)
			b.Policy.BackupReservedBytes = backup * b.Policy.MetadataSlots
			b.Policy.WALReservedBytes = wal * b.Policy.MetadataSlots
		}},
		{"pool backup increase", func(b *ConnectorIdentityBacking) { b.Policy.BackupReservedBytes++ }},
		{"pool WAL increase", func(b *ConnectorIdentityBacking) { b.Policy.WALReservedBytes++ }},
		{"backup horizon", func(b *ConnectorIdentityBacking) { b.Policy.BackupHorizonSeconds++ }},
		{"cleanup budget", func(b *ConnectorIdentityBacking) { b.Policy.CleanupBudgetSeconds++ }},
		{"proof window", func(b *ConnectorIdentityBacking) { b.Policy.ProofWindowSeconds++ }},
		{"purge allowance", func(b *ConnectorIdentityBacking) { b.Policy.MaxPurgeLeases++; connectorRenewalPoolBacking(b) }},
		{"qualification identity", func(b *ConnectorIdentityBacking) { b.Policy.History.ID = "20000000-0000-4000-8000-000000000002" }},
		{"qualification digest", func(b *ConnectorIdentityBacking) { b.Policy.History.Digest[0]++ }},
		{"qualified row size", func(b *ConnectorIdentityBacking) {
			b.Policy.History.MaximumRowFootprintBytes++
			b.SourceBackupReservedBytes = 2 * (b.ProfileLimit + 1) * b.Policy.History.MaximumRowFootprintBytes * b.Policy.History.BackupCopies
			connectorRenewalPoolBacking(b)
		}},
		{"qualified WAL size", func(b *ConnectorIdentityBacking) {
			b.Policy.History.MaximumTransitionWALBytes++
			b.SourceWALReservedBytes = 2 * b.SourceTransitionLimit * b.Policy.History.MaximumTransitionWALBytes * b.Policy.History.WALCopies
			connectorRenewalPoolBacking(b)
		}},
		{"backup copies", func(b *ConnectorIdentityBacking) {
			b.Policy.History.BackupCopies++
			b.SourceBackupReservedBytes = 2 * (b.ProfileLimit + 1) * b.Policy.History.MaximumRowFootprintBytes * b.Policy.History.BackupCopies
			connectorRenewalPoolBacking(b)
		}},
		{"WAL copies", func(b *ConnectorIdentityBacking) {
			b.Policy.History.WALCopies++
			b.SourceWALReservedBytes = 2 * b.SourceTransitionLimit * b.Policy.History.MaximumTransitionWALBytes * b.Policy.History.WALCopies
			connectorRenewalPoolBacking(b)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := previous.Clone()
			next.Policy.BackingRevision++
			next.Policy.ValidUntil = next.Policy.ValidUntil.Add(time.Hour)
			tc.edit(&next)
			if !next.Valid() {
				t.Fatal("test did not isolate a valid but incompatible backing")
			}
			if next.CanRenew(previous) {
				t.Fatal("renewal changed previously accepted resources or qualification")
			}
		})
	}
	bad := previous.Clone()
	bad.Policy.History = nil
	next := previous.Clone()
	next.Policy.BackingRevision++
	next.Policy.ValidUntil = next.Policy.ValidUntil.Add(time.Hour)
	if next.CanRenew(bad) || bad.CanRenew(previous) {
		t.Fatal("invalid historical or proposed backing admitted")
	}
}

func TestConnectorBackingRenewalPreservesOriginalValuesAndAliasedQualification(t *testing.T) {
	previous := connectorRenewalBacking(t)
	// Deliberately share the immutable qualification pointer. A comparison must
	// never normalize inputs in place or silently replace original policy dates.
	next := previous
	next.Policy.BackingRevision++
	next.Policy.ValidUntil = next.Policy.ValidUntil.Add(time.Hour)
	beforePrevious, beforeNext := previous.Clone(), next.Clone()
	if !next.CanRenew(previous) || !next.CanRenew(previous) {
		t.Fatal("exact compatible comparison is not repeatable")
	}
	if !reflect.DeepEqual(previous, beforePrevious) || !reflect.DeepEqual(next, beforeNext) {
		t.Fatal("renewal comparison rewrote original dates or shared qualification")
	}
	independent := next.Clone()
	independent.Policy.History.Digest[0]++
	if independent.CanRenew(previous) || !reflect.DeepEqual(previous, beforePrevious) || !reflect.DeepEqual(next, beforeNext) {
		t.Fatal("cloned qualification changed existing backing")
	}
}

func TestConnectorBackingSourceBudgetIncludesRoot(t *testing.T) {
	for _, copies := range []int64{1, 3} {
		for _, profiles := range []int64{1, 2, 8} {
			b := connectorRenewalBacking(t)
			b.ProfileLimit, b.AccountLimit = profiles, profiles
			b.Policy.History.BackupCopies = copies
			connectorRenewalPoolBacking(&b)
			floor := 2 * (profiles + 1) * b.Policy.History.MaximumRowFootprintBytes * copies
			b.SourceBackupReservedBytes = floor
			if !b.Valid() {
				t.Fatal("exact separately backed root/profile allowance denied", profiles, copies)
			}
			b.SourceBackupReservedBytes--
			if b.Valid() {
				t.Fatal("source root shares already allocated profile backup bytes", profiles, copies)
			}
		}
	}
}

func TestConnectorBackingDeploymentIncludesRetainedRenewalAllowance(t *testing.T) {
	f, _ := connectorSourceConfiguration(t)
	d := f.cfg.Source.Observation.Profile.Deployment
	for _, transitions := range []int64{2, 10, 32} {
		b := connectorRenewalBacking(t)
		b.SourceTransitionLimit = transitions
		b.SourceWALReservedBytes = 2 * transitions * b.Policy.History.MaximumTransitionWALBytes * b.Policy.History.WALCopies
		// This fixture has eight retained processes and two serving slots over
		// three hours: forty process + fifty-six signing records. Every root
		// transition may land on this same peer, including uncertain closed ones.
		b.RecordsPerAccount = 96 + transitions
		connectorRenewalPoolBacking(&b)
		if !b.Valid() || !b.SupportsDeployment(d) {
			t.Fatal("exact retained process/signing/renewal allowance denied", transitions)
		}
		b.RecordsPerAccount--
		connectorRenewalPoolBacking(&b)
		if !b.Valid() {
			t.Fatal("test exhausted structural pool rather than renewal record allowance")
		}
		if b.SupportsDeployment(d) {
			t.Fatal("backing renewal can consume capacity reserved for process/signing", transitions)
		}
	}
}
