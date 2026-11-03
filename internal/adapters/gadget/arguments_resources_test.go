package gadget

import "testing"

func TestArgumentWorkingSetIncludesActualPerfPagesAndMaps(t *testing.T) {
	for _, tc := range []struct {
		cpus, page, threads int
		want                int64
	}{{256, 4096, 4096, 27 << 20}, {256, 65536, 4096, 162 << 20}, {256, 4096, 16384, 75 << 20}} {
		got, err := ArgumentWorkingSet(tc.cpus, tc.page, tc.threads)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	for _, tc := range [][3]int{{0, 4096, 1}, {257, 4096, 1}, {1, 8193, 1}, {1, 4096, 16385}} {
		if _, err := ArgumentWorkingSet(tc[0], tc[1], tc[2]); err == nil {
			t.Fatal(tc)
		}
	}
}
