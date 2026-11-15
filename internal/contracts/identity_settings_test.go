package contracts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Absent administrators are omitted, never marshalled as an empty object
// the schema refuses; present ones round-trip.
func TestIdentitySettingsAdministratorsRoundTrip(t *testing.T) {
	b, err := json.Marshal(IdentitySettings{})
	if err != nil || strings.Contains(string(b), "administrators") {
		t.Fatal(string(b), err)
	}
	in := IdentitySettings{Administrators: &IdentityAdministrators{Groups: []string{"admins"}, Subjects: []string{"sub"}}}
	b, err = json.Marshal(in)
	var out IdentitySettings
	if err != nil || json.Unmarshal(b, &out) != nil || !reflect.DeepEqual(in, out) {
		t.Fatal(string(b), err)
	}
}
