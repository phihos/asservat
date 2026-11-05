package artifact

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRecordedArgumentValueQualifiedEncodingIsExact(t *testing.T) {
	for _, a := range []ArgumentValue{
		{Name: "fd", Value: "decimal:-2147483648"}, {Name: "dirfd", Value: "decimal:0"}, {Name: "count", Value: "decimal:18446744073709551615"}, {Name: "offset", Value: "decimal:-9223372036854775808"}, {Name: "flags", Value: "decimal:4294967295"}, {Name: "mode", Value: "decimal:0"}, {Name: "buffer", Value: "base64:"}, {Name: "path", Value: "unavailable:fault"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString(make([]byte, 128)), Truncated: true},
	} {
		before := a
		if !a.WellFormed() || a != before {
			t.Fatal("qualified value changed/refused", a.Name)
		}
	}
	for _, a := range []ArgumentValue{
		{Name: "fd", Value: "decimal:2147483648"}, {Name: "fd", Value: "decimal:-0"}, {Name: "count", Value: "decimal:+1"}, {Name: "count", Value: "decimal:01"}, {Name: "count", Value: "decimal:-1"}, {Name: "count", Value: "decimal:18446744073709551616"}, {Name: "offset", Value: "decimal:-9223372036854775809"}, {Name: "flags", Value: "decimal:4294967296"}, {Name: "mode", Value: "decimal:0", Truncated: true}, {Name: "buffer", Value: "unavailable:fault", Truncated: true}, {Name: "buffer", Value: "base64:Zh=="}, {Name: "buffer", Value: "base64:Zg==\n"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString(make([]byte, 129))}, {Name: "buffer", Value: "hex:00"}, {Name: "buffer", Value: "decimal:1"}, {Name: "fd", Value: "base64:"}, {Name: "address", Value: "decimal:1"}, {Name: "path", Value: strings.Repeat("x", 180)},
	} {
		if a.WellFormed() {
			t.Fatal("unqualified value accepted", a.Name, a.Value)
		}
	}
}
