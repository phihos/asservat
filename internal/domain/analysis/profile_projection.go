package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

// ProfileSummaryRequest names one artifact and a closed display selection.
// It carries no source classification, authority, worker or resource budget.
type ProfileSummaryRequest struct {
	CaseID, ArtifactID string
	Selection          ProfileSummarySelection
}

func (r ProfileSummaryRequest) Valid() bool {
	return authorization.UUID(r.CaseID) && authorization.UUID(r.ArtifactID) && r.Selection.Valid()
}

// ProfileComparisonRequest is normalized public selection of two ordered
// artifacts. Private routes, versions, placement and authority are absent.
type ProfileComparisonRequest struct {
	CaseID, ArtifactID, BaselineCaseID, BaselineArtifactID string
	Selection                                              ProfileComparisonSelection
}

func (r ProfileComparisonRequest) Valid() bool {
	return authorization.UUID(r.CaseID) && authorization.UUID(r.ArtifactID) && authorization.UUID(r.BaselineCaseID) && authorization.UUID(r.BaselineArtifactID) && (r.ArtifactID != r.BaselineArtifactID || r.CaseID == r.BaselineCaseID) && r.Selection.Valid()
}

// ReadOperation separates permission to disclose a qualified aggregate from
// permission to disclose the original raw evidence. A caller cannot invent a
// source definition: the entire value must equal the closed registry entry.
func (s ProjectionSource) ReadOperation() authorization.Operation {
	known, ok := LookupProjectionSourceFor(s.NativeType, s.DisplayVersion)
	if !ok || known != s {
		return ""
	}
	if s.DisplayVersion == LogQueryDisplayVersion {
		return authorization.ReadLogQuery
	}
	if s.DisplayVersion == SyscallQueryDisplayVersion {
		return authorization.ReadSyscallQuery
	}
	if s.DisplayVersion == PacketQueryDisplayVersion {
		return authorization.ReadPacketQuery
	}
	if s.NativeType == artifact.RawPCAPNGArtifact {
		return authorization.ReadPacketSummary
	}
	if s.NativeType == artifact.PprofArtifact {
		return authorization.ReadProfileSummary
	}
	if s.NativeType == artifact.SyscallArgumentsArtifact {
		return authorization.ReadSyscallProjection
	}
	return authorization.ReadApproved
}

// OutputClass is the classification of the closed result, not of its input.
func (s ProjectionSource) OutputClass() string {
	if s.ReadOperation() == "" {
		return ""
	}
	if s.DisplayVersion == SyscallQueryDisplayVersion {
		return "raw"
	}
	if s.DisplayVersion == PacketQueryDisplayVersion {
		if s.NativeType == artifact.RawPCAPNGArtifact {
			return "raw"
		}
		return "extract"
	}
	if s.NativeType == artifact.PCAPNGArtifact || s.NativeType == artifact.RawPCAPNGArtifact || s.NativeType == artifact.PprofArtifact || s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact {
		return "extract"
	}
	return s.DataClass
}

// CloneProfileSummary owns all pointers in a prepared result. Returning a copy
// must not let a consumer mutate the worker's retained disclosure value.
func CloneProfileSummary(s ProfileSummary) ProfileSummary {
	if s.DurationSeconds != nil {
		v := *s.DurationSeconds
		s.DurationSeconds = &v
	}
	if s.Top != nil {
		s.Top = append([]ProfileHotspot{}, s.Top...)
		for i := range s.Top {
			if s.Top[i].Function != nil {
				v := *s.Top[i].Function
				s.Top[i].Function = &v
			}
			if s.Top[i].Fraction != nil {
				v := *s.Top[i].Fraction
				s.Top[i].Fraction = &v
			}
		}
	}
	return s
}
