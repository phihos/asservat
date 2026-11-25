package hub

import (
	"context"
	"slices"
	"testing"
)

// A watch records for the one who made it, with what they may do today
// where the hub knows that: a user of the hub's own list has the groups
// the list gives now, and one who was taken off the list has none and
// records nothing more. Of a user of an identity provider the hub knows
// only what the token said when the watch was made.
func TestAWatchRecordsWithTodaysGroups(t *testing.T) {
	h := &Hub{Config: Config{AdminGroups: []string{"admins"}, Users: []StaticUser{{Name: "alice", Token: "t", Groups: []string{"payments"}}}}}
	if u, err := h.creator("alice", []string{"payments", "admins"}); err != nil || !slices.Equal(u.Groups, []string{"payments"}) || u.Admin {
		t.Fatal("a user who left a group keeps it for their watches:", u, err)
	}
	if _, err := h.creator("bob", []string{"admins"}); err == nil {
		t.Fatal("a user who is no longer on the list still records")
	}
	// With an identity provider, a name that is not on the list is one of its users.
	h.Verify = func(_ context.Context, _ string) (User, error) { return User{}, nil }
	if u, err := h.creator("carol", []string{"admins"}); err != nil || !u.Admin {
		t.Fatal("a user of the identity provider:", u, err)
	}
}
