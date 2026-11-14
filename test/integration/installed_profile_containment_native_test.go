package integration

import (
	"os"
)

type acceptedHeavyInput struct {
	Filename                 string            `json:"filename"`
	Side                     string            `json:"side"`
	Functions                int               `json:"functions"`
	Locations                int               `json:"locations"`
	Samples                  int               `json:"samples"`
	FrameVisits              int               `json:"frame_visits"`
	SampleLocationReferences int               `json:"sample_location_references"`
	InlineLines              int               `json:"inline_lines"`
	ValuesPerSample          int               `json:"values_per_sample"`
	SampleTypes              int               `json:"sample_types"`
	NumericLabels            int               `json:"numeric_label_records_with_units"`
	StringTableEntries       int               `json:"string_table_entries"`
	SharedUnits              int               `json:"shared_object_units"`
	ProtobufBytes            int64             `json:"protobuf_bytes"`
	NativeBytes              int64             `json:"native_bytes"`
	ProtobufSHA256           string            `json:"protobuf_sha256"`
	NativeSHA256             string            `json:"native_sha256"`
	Files                    map[string]string `json:"encrypted_fixture_sha256"`
}

type acceptedHeavyManifest struct {
	Format                string               `json:"format"`
	GeneratorBinarySHA256 string               `json:"generator_binary_sha256"`
	GoVersion             string               `json:"go_version"`
	ProfileType           string               `json:"profile_type"`
	SampleType            string               `json:"sample_type"`
	Unit                  string               `json:"unit"`
	DurationNanos         int64                `json:"duration_ns"`
	Inputs                []acceptedHeavyInput `json:"inputs"`
}
type installedProfileContainmentFixture struct {
	ResourceProbeSHA256 string
	OutputDirectory     string // Private harness work directory, collected explicitly at terminal.
	Manifest            acceptedHeavyManifest
}

func installedAcceptedHeavyComparison() bool {
	if os.Getenv("ASSERVAT_PROFILE_VARIANT") != "accepted-heavy" {
		return false
	}
	if installedJourneyFocus() != "profile-comparison" {
		panic("accepted-heavy variant requires profile-comparison focus")
	}
	return true
}
