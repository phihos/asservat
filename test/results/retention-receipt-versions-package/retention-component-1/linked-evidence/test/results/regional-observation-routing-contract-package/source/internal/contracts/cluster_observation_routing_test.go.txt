package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func routingWireValues() (ClusterObservationLocatorQuery, ClusterObservationClaim) {
	id := func(s string) string { return s + "0000000-0000-0000-0000-000000000001" }
	q := ClusterObservationLocatorQuery{ClusterObservationLocatorFormat, id("1"), id("2"), id("3"), id("4"), "2026-10-13T12:00:00.123456789Z", "2026-10-13T12:00:05.123456789Z"}
	v := ClusterObservationLocator{Format: ClusterObservationLocatorFormat, RootID: q.RootID, ClusterID: q.ClusterID, RequestID: q.RequestID, Challenge: q.Challenge, Holder: ClusterObservationHolder{id("a"), id("5"), id("6"), id("7"), id("8")}, ExchangeID: id("9"), Sequence: 1, ObservedAt: "2026-10-13T12:00:01.123456789Z", FreshUntil: "2026-10-13T12:00:04.123456789Z"}
	r := ClusterObservationRequest{Format: ClusterObservationFormat, RootID: q.RootID, ClusterID: q.ClusterID, RequestID: q.RequestID, Challenge: q.Challenge, RequestedAt: q.RequestedAt, NotAfter: q.NotAfter, Purpose: ClusterObservationNamespaceGuard}
	return q, ClusterObservationClaim{ClusterObservationClaimFormat, r, v}
}

func TestClusterObservationRoutingCanonicalTarget(t *testing.T) {
	q, _ := routingWireValues()
	target, err := EncodeClusterObservationLocatorTarget(q)
	if err != nil || len(target) > ClusterObservationLocatorTargetBytes {
		t.Fatal("valid target rejected")
	}
	got, err := DecodeClusterObservationLocatorTarget(target)
	if err != nil || got != q {
		t.Fatal("target lost original tuple or dates")
	}
	// Query ordering and percent-encoding have one accepted representation.
	parts := strings.Split(strings.SplitN(target, "?", 2)[1], "&")
	for name, input := range map[string]string{
		"empty": "", "over-bound": strings.Repeat("x", ClusterObservationLocatorTargetBytes+1),
		"absolute": "https://owner.invalid" + target, "userinfo": "https://user@owner.invalid" + target,
		"claim-path":   strings.Replace(target, ClusterObservationLocatorPath, ClusterObservationClaimPath, 1),
		"encoded-path": strings.Replace(target, "/internal/", "/%69nternal/", 1),
		"relative":     target[1:], "double-slash": "/" + target, "fragment": target + "#fragment",
		"unknown": target + "&token=not-a-token", "duplicate": target + "&challenge=" + q.Challenge,
		"empty-duplicate": target + "&challenge", "missing": strings.Replace(target, parts[0]+"&", "", 1),
		"alias":             strings.Replace(target, "requestID=", "requestId=", 1),
		"order":             ClusterObservationLocatorPath + "?" + parts[1] + "&" + parts[0] + "&" + strings.Join(parts[2:], "&"),
		"lowercase-escape":  strings.Replace(target, "%2F", "%2f", 1),
		"unescaped-time":    strings.Replace(target, "%3A", ":", 1),
		"escape-unreserved": strings.Replace(target, "challenge=4", "challenge=%34", 1),
		"empty-key":         target + "&", "semicolon": target + ";extra=1", "bad-escape": target + "%zz",
		"wrong-format": strings.Replace(target, "locator%2Fv1", "claim%2Fv1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if input == target {
				t.Fatal("negative fixture did not change target")
			}
			if _, err := DecodeClusterObservationLocatorTarget(input); err == nil {
				t.Fatal("noncanonical or foreign target accepted")
			}
		})
	}
}

func TestClusterObservationRoutingRejectsDatesAndIDs(t *testing.T) {
	base, _ := routingWireValues()
	for name, mutate := range map[string]func(*ClusterObservationLocatorQuery){
		"zero":              func(q *ClusterObservationLocatorQuery) { q.RequestedAt = "0001-01-01T00:00:00Z" },
		"invalid":           func(q *ClusterObservationLocatorQuery) { q.RequestedAt = "not-a-time" },
		"offset":            func(q *ClusterObservationLocatorQuery) { q.RequestedAt = "2026-10-13T12:00:00.123456789+00:00" },
		"fraction-zero":     func(q *ClusterObservationLocatorQuery) { q.RequestedAt = "2026-10-13T12:00:00.000Z" },
		"excess-precision":  func(q *ClusterObservationLocatorQuery) { q.RequestedAt = "2026-10-13T12:00:00.1234567891Z" },
		"comma":             func(q *ClusterObservationLocatorQuery) { q.RequestedAt = "2026-10-13T12:00:00,123456789Z" },
		"empty-interval":    func(q *ClusterObservationLocatorQuery) { q.NotAfter = q.RequestedAt },
		"backwards":         func(q *ClusterObservationLocatorQuery) { q.NotAfter = "2026-10-13T11:59:59Z" },
		"over-five-seconds": func(q *ClusterObservationLocatorQuery) { q.NotAfter = "2026-10-13T12:00:05.12345679Z" },
		"missing-id":        func(q *ClusterObservationLocatorQuery) { q.RequestID = "" },
		"zero-id":           func(q *ClusterObservationLocatorQuery) { q.RootID = "00000000-0000-0000-0000-000000000000" },
		"uppercase-id":      func(q *ClusterObservationLocatorQuery) { q.Challenge = "A0000000-0000-0000-0000-000000000001" },
		"purpose":           func(q *ClusterObservationLocatorQuery) { q.Format = ClusterObservationClaimFormat },
	} {
		t.Run(name, func(t *testing.T) {
			q := base
			mutate(&q)
			if _, err := EncodeClusterObservationLocatorTarget(q); err == nil {
				t.Fatal("invalid query encoded")
			}
		})
	}
}

func TestClusterObservationRoutingExactUint64(t *testing.T) {
	_, c := routingWireValues()
	for _, n := range []uint64{1, 1<<53 - 1, 1 << 53, 1<<53 + 1, ^uint64(0) - 1, ^uint64(0)} {
		t.Run(strconv.FormatUint(n, 10), func(t *testing.T) {
			c.Locator.Sequence = n
			body, err := EncodeClusterObservationLocator(c.Locator)
			if err != nil || !bytes.Contains(body, []byte(`"sequence":`+strconv.FormatUint(n, 10))) {
				t.Fatal("integer spelling changed")
			}
			v, err := DecodeClusterObservationLocator(body)
			if err != nil || v != c.Locator {
				t.Fatal("locator integer rounded or rejected")
			}
			body, err = EncodeClusterObservationClaim(c)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := DecodeClusterObservationClaim(body)
			if err != nil || claim.Locator.Sequence != n {
				t.Fatal("nested integer rounded or rejected")
			}
		})
	}
	c.Locator.Sequence = 1
	body, err := EncodeClusterObservationLocator(c.Locator)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"0", "-0", "-1", "18446744073709551616", "9007199254740993.0", "1e0", `"1"`, "null", "true", "01"} {
		t.Run("reject-"+n, func(t *testing.T) {
			b := bytes.Replace(body, []byte(`"sequence":1`), []byte(`"sequence":`+n), 1)
			if _, err := DecodeClusterObservationLocator(b); err == nil {
				t.Fatal("invalid sequence accepted")
			}
		})
	}
}

func TestClusterObservationRoutingClosedJSON(t *testing.T) {
	_, c := routingWireValues()
	body, err := EncodeClusterObservationClaim(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"unknown":                append([]byte(`{"token":"private",`), body[1:]...),
		"duplicate":              append([]byte(`{"format":"cluster-observation-claim/v1",`), body[1:]...),
		"nested-unknown":         bytes.Replace(body, []byte(`"holder":{`), []byte(`"holder":{"url":"https://other.invalid",`), 1),
		"nested-duplicate":       bytes.Replace(body, []byte(`"holder":{`), []byte(`"holder":{"podUid":"`+c.Locator.Holder.PodUID+`",`), 1),
		"nested-alias":           bytes.Replace(body, []byte(`"podUid"`), []byte(`"PodUid"`), 1),
		"nested-missing":         bytes.Replace(body, []byte(`,"sequence":1`), nil, 1),
		"nested-null":            bytes.Replace(body, []byte(`"sequence":1`), []byte(`"sequence":null`), 1),
		"request-unknown":        bytes.Replace(body, []byte(`"request":{`), []byte(`"request":{"token":"private",`), 1),
		"request-null":           bytes.Replace(body, []byte(`"purpose":"`+c.Request.Purpose+`"`), []byte(`"purpose":null`), 1),
		"wrong-envelope-purpose": bytes.Replace(body, []byte(ClusterObservationClaimFormat), []byte(ClusterObservationLocatorFormat), 1),
		"wrong-locator-purpose":  bytes.Replace(body, []byte(ClusterObservationLocatorFormat), []byte(ClusterObservationClaimFormat), 1),
		"wrong-request-purpose":  bytes.Replace(body, []byte(c.Request.Purpose), []byte("capture"), 1),
		"trailing":               append(bytes.Clone(body), []byte(`{}`)...),
		"over-bound":             bytes.Repeat([]byte(" "), ClusterObservationClaimBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(b, body) {
				t.Fatal("negative fixture unchanged")
			}
			if _, err := DecodeClusterObservationClaim(b); err == nil {
				t.Fatal("nonclosed claim accepted")
			}
		})
	}
	if _, err := DecodeClusterObservationLocator(bytes.Repeat([]byte(" "), ClusterObservationLocatorBytes+1)); err == nil {
		t.Fatal("oversized locator accepted")
	}
	if _, err := DecodeClusterObservationLocator(body); err == nil {
		t.Fatal("claim accepted as locator")
	}
	v, _ := EncodeClusterObservationLocator(c.Locator)
	if _, err := DecodeClusterObservationClaim(v); err == nil {
		t.Fatal("locator accepted as claim")
	}
}

func TestClusterObservationRoutingClaimRetainsOriginalBounds(t *testing.T) {
	_, base := routingWireValues()
	for name, mutate := range map[string]func(*ClusterObservationClaim){
		"request":              func(c *ClusterObservationClaim) { c.Locator.RequestID = c.Request.Challenge },
		"challenge":            func(c *ClusterObservationClaim) { c.Locator.Challenge = c.Request.RequestID },
		"root":                 func(c *ClusterObservationClaim) { c.Locator.RootID = c.Request.ClusterID },
		"cluster":              func(c *ClusterObservationClaim) { c.Locator.ClusterID = c.Request.RootID },
		"holder":               func(c *ClusterObservationClaim) { c.Locator.Holder.InstallationID = "" },
		"prior-observation":    func(c *ClusterObservationClaim) { c.Locator.ObservedAt = "2026-10-13T12:00:00Z" },
		"extended-observation": func(c *ClusterObservationClaim) { c.Locator.FreshUntil = "2026-10-13T12:00:05.12345679Z" },
		"request-format":       func(c *ClusterObservationClaim) { c.Request.Format = ClusterObservationClaimFormat },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, err := EncodeClusterObservationClaim(c); err == nil {
				t.Fatal("contradictory or extended selection encoded")
			}
		})
	}
}

func TestClusterObservationRoutingRetainsFourRequestEncodings(t *testing.T) {
	_, base := routingWireValues()
	for _, purpose := range []string{ClusterObservationNamespaceGuard, ClusterObservationNamespaces, ClusterObservationWorkloads, ClusterObservationWorkload} {
		t.Run(purpose, func(t *testing.T) {
			c := base
			c.Request.Purpose = purpose
			switch purpose {
			case ClusterObservationNamespaces:
				c.Request.Continue = "page"
			case ClusterObservationWorkloads:
				c.Request.Namespace = &ClusterObservationNamespace{"sample", "ns"}
				c.Request.Kind = "Pod"
			case ClusterObservationWorkload:
				c.Request.Namespace = &ClusterObservationNamespace{"sample", "ns"}
				c.Request.Workload = &ClusterObservationWorkloadRef{"Deployment", "sample", "workload"}
				c.Request.Keys = []string{"z", "a<>&"}
			}
			for _, empty := range []bool{false, true} {
				if empty && purpose != ClusterObservationWorkload {
					c.Request.Keys = []string{}
				}
				original, err := EncodeClusterObservationRequest(c.Request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := EncodeClusterObservationClaim(c)
				if err != nil {
					t.Fatal(err)
				}
				var raw struct{ Request json.RawMessage }
				if json.Unmarshal(body, &raw) != nil || !bytes.Equal(raw.Request, original) {
					t.Fatal("existing canonical request bytes changed inside envelope")
				}
				got, err := DecodeClusterObservationClaim(body)
				if err != nil {
					t.Fatal(err)
				}
				round, _ := EncodeClusterObservationRequest(got.Request)
				if !bytes.Equal(round, original) {
					t.Fatal("request reencoding changed")
				}
				if purpose == ClusterObservationWorkload && !reflect.DeepEqual(got.Request.Keys, c.Request.Keys) {
					t.Fatal("selector order changed")
				}
			}
		})
	}
}

func TestClusterObservationRoutingMaximumRequest(t *testing.T) {
	_, c := routingWireValues()
	c.Locator.Sequence = ^uint64(0)
	c.Request.Purpose = ClusterObservationWorkload
	c.Request.Namespace = &ClusterObservationNamespace{strings.Repeat(`"`, 63), strings.Repeat(`\`, 64)}
	c.Request.Workload = &ClusterObservationWorkloadRef{"StatefulSet", strings.Repeat(`\`, 253), strings.Repeat(`"`, 64)}
	c.Request.Keys = make([]string, ClusterObservationSelectorKeys)
	for i := range c.Request.Keys {
		c.Request.Keys[i] = fmt.Sprintf("%03d", i) + strings.Repeat(`"`, 250)
	}
	body, err := EncodeClusterObservationClaim(c)
	if err != nil || len(body) > ClusterObservationClaimBytes {
		t.Fatal("bounded maximum request does not fit envelope")
	}
	if _, err := DecodeClusterObservationClaim(body); err != nil {
		t.Fatal("maximum request failed closed decoder")
	}
}
