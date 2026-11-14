package integration

import (
	"encoding/json"
	"reflect"
)

func installedDeletionSamePolicy(a, b string) bool {
	var x, y any
	return json.Unmarshal([]byte(a), &x) == nil && json.Unmarshal([]byte(b), &y) == nil && reflect.DeepEqual(x, y)
}
