package kubernetes

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

func runtimeRoundtripDifferencePaths(want, got []byte) []string {
	var a, b any
	_ = json.Unmarshal(want, &a)
	_ = json.Unmarshal(got, &b)
	var paths []string
	var walk func(string, any, any)
	walk = func(path string, a, b any) {
		if reflect.DeepEqual(a, b) {
			return
		}
		am, ao := a.(map[string]any)
		bm, bo := b.(map[string]any)
		if ao && bo {
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range bm {
				keys[k] = true
			}
			for k := range keys {
				walk(path+"."+k, am[k], bm[k])
			}
			return
		}
		aa, ao := a.([]any)
		bb, bo := b.([]any)
		if ao && bo && len(aa) == len(bb) {
			for i := range aa {
				walk(fmt.Sprintf("%s[%d]", path, i), aa[i], bb[i])
			}
			return
		}
		paths = append(paths, path)
	}
	walk("$", a, b)
	sort.Strings(paths)
	if len(paths) > 32 {
		paths = paths[:32]
	}
	return paths
}
