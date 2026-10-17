package capacity

import (
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func capacityQualificationFixture() (CapacityQualification, ProtectedPoolPlan) {
	in, p := capacityRootBackingFixture()
	p.StorageProfile = "protected-store"
	p.Capacity = BudgetAmount{1 << 40, 10000000}
	p.System = p.Capacity
	q := CapacityQualification{ID: in.QualificationID, Digest: in.QualificationDigest, RootBacking: in,
		NamespaceGuards: []CapacityNamespaceQualification{{ClusterID: in.RootID, Digest: artifact.Digest{4}, Keys: []string{"asservat.example/team"}}},
		Backends:        []CapacityBackendQualification{{Layout: CapacityBackendLayout, ID: in.QualificationID, Digest: artifact.Digest{7}, PoolUID: p.UID, StorageProfile: p.StorageProfile, CapacityID: "30000000-0000-4000-8000-000000000005", PoolID: "30000000-0000-4000-8000-000000000006", EvidenceStoreID: "30000000-0000-4000-8000-000000000007", AuditStoreID: in.Capture.Policy.StoreID, Usable: p.Capacity}},
	}
	return q, p
}

func TestCapacityBackendQualificationBindsActualDedicatedEnvelope(t *testing.T) {
	q, p := capacityQualificationFixture()
	if !q.Valid() {
		t.Fatal("qualification fixture invalid")
	}
	if _, e := CompileQualifiedRootBacking(q, p); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"wrong-store", "pool-replacement", "profile-change", "bytes", "objects", "duplicate-capacity", "duplicate-pool", "duplicate-store", "foreign-namespace-key"} {
		t.Run(name, func(t *testing.T) {
			v, p := capacityQualificationFixture()
			switch name {
			case "wrong-store":
				v.Backends[0].AuditStoreID = "30000000-0000-4000-8000-000000000008"
			case "pool-replacement":
				p.UID = "replacement"
			case "profile-change":
				p.StorageProfile = "other"
			case "bytes":
				p.Capacity.Bytes++
			case "objects":
				p.Capacity.Objects++
			case "foreign-namespace-key":
				v.NamespaceGuards[0].Keys = []string{"z", "a"}
			default:
				b := v.Backends[0]
				b.PoolUID = "second"
				b.PoolID = "30000000-0000-4000-8000-000000000009"
				b.EvidenceStoreID = "30000000-0000-4000-8000-000000000010"
				b.CapacityID = "30000000-0000-4000-8000-000000000011"
				if name == "duplicate-capacity" {
					b.CapacityID = v.Backends[0].CapacityID
				}
				if name == "duplicate-pool" {
					b.PoolID = v.Backends[0].PoolID
				}
				if name == "duplicate-store" {
					b.EvidenceStoreID = v.Backends[0].EvidenceStoreID
				}
				v.Backends = append(v.Backends, b)
			}
			if _, e := CompileQualifiedRootBacking(v, p); e == nil {
				t.Fatal("unowned or doubly pledged backend accepted")
			}
		})
	}
}
