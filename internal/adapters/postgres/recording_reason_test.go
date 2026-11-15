package postgres

import (
	"reflect"
	"testing"
)

// ADR-330 D8: the reviewed reason is plain blueprint data and reads back
// unchanged; a changed blueprint fails its digest.
func TestReasonPreviewIsBlueprintData(t *testing.T) {
	p := previewTestValue(t)
	reason := "investigate user data"
	p.Intent.Reason = &reason
	row := previewTestRow(t, p)
	got, err := previewRecord(row)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("stored reason lost", err)
	}
	row.BlueprintJson = append([]byte(nil), row.BlueprintJson...)
	row.BlueprintJson[len(row.BlueprintJson)-2] ^= 1
	if _, err = previewRecord(row); err == nil {
		t.Fatal("changed blueprint accepted")
	}
}
