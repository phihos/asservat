package kubernetes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
)

// Alertmanager answer bounds (ADR-231). The v2 alerts API has no paging: an
// answer larger than alertBodyLimit or with more than alertLimit alerts of
// the namespace is not observed (Unknown).
const (
	alertBodyLimit = 1 << 20
	alertLimit     = 1024
)

// Alertmanager reads active alerts from the cluster's in-cluster Alertmanager
// v2 API for alert policies (ADR-231). Its address is installation-owned
// regional configuration, never policy input. It sends no credential and
// follows no redirect; alert labels and annotations never leave the region.
type Alertmanager struct {
	alerts string
	client *http.Client
}

// AlertmanagerURL reports whether raw is an acceptable Alertmanager base URL:
// http or https, a host, an optional path prefix (--web.route-prefix), and
// no credentials, query or fragment.
func AlertmanagerURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 512 && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && !strings.Contains(raw, "#") && u.RawPath == "" && !strings.ContainsAny(u.Host, "/\\@?#% \t\r\n")
}

// NewAlertmanager returns the regional Alertmanager reader for base, or
// ErrInvalid. https uses the system roots.
func NewAlertmanager(base string) (*Alertmanager, error) {
	if !AlertmanagerURL(base) {
		return nil, value.ErrInvalid
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Alertmanager{alerts: strings.TrimSuffix(base, "/") + "/api/v2/alerts", client: client}, nil
}

// WithAlertmanager returns c observing alert policies through a; without it
// an alert observation is unsupported (activation refuses the policy).
func (c *PodTargets) WithAlertmanager(a *Alertmanager) *PodTargets {
	out := *c
	out.alerts = a
	return &out
}

// firing adds the ADR-231 alert data to the observed Pods from one GET of the
// namespace's active, unsilenced and uninhibited alerts. An alert counts for
// a Pod when its namespace label is the workload's namespace, its pod label
// names an observed Pod and every requested label matches; it contributes
// one to the Pod's level and its startsAt second (clamped to now) to the
// newest alert time. Alerts without a pod label are ignored: the policy
// captures the triggering Pod only. Unreachable, non-200, oversized or
// malformed answers fail, so the poll is Unknown and fires nothing.
func (a *Alertmanager) firing(ctx context.Context, namespace string, match map[string]string, now time.Time, pods []value.PodRestarts) error {
	index := make(map[string]int, len(pods))
	names := make([]string, 0, len(pods))
	for i, p := range pods {
		index[p.Name] = i
		names = append(names, p.Name)
	}
	if len(names) == 0 {
		return nil
	}
	// The pod matcher narrows the answer to this workload's Pods, so alerts of
	// other workloads in the namespace cannot reach the answer bounds. Pod
	// names are DNS subdomains: an unescaped "." only widens the server-side
	// match, and the exact name check below still applies. matchLabels stay
	// client-side: arbitrary values would need Alertmanager's quoting rules.
	slices.Sort(names)
	query := url.Values{"active": {"true"}, "silenced": {"false"}, "inhibited": {"false"}, "filter": {`namespace="` + namespace + `"`, `pod=~"` + strings.Join(names, "|") + `"`}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.alerts+"?"+query.Encode(), nil)
	if err != nil {
		return value.ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return value.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return value.ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, alertBodyLimit+1))
	if err != nil {
		return value.ErrUnavailable
	}
	if len(body) > alertBodyLimit {
		return value.ErrLimit
	}
	var alerts []struct {
		Labels   map[string]string
		StartsAt string
		Status   struct{ State string }
	}
	if json.Unmarshal(body, &alerts) != nil || alerts == nil {
		return value.ErrUnavailable
	}
	if len(alerts) > alertLimit {
		return value.ErrLimit
	}
	for _, alert := range alerts {
		// Only alerts of this policy are validated: a malformed alert of
		// another workload must not make this poll Unknown.
		i, owned := index[alert.Labels["pod"]]
		if alert.Labels["namespace"] != namespace || !owned || !labelsMatch(alert.Labels, match) {
			continue
		}
		switch alert.Status.State {
		case "active", "unprocessed":
		case "suppressed":
			continue
		default:
			return value.ErrUnavailable
		}
		started, err := time.Parse(time.RFC3339Nano, alert.StartsAt)
		if err != nil || started.Unix() < value.MinProbeLast || started.Unix() >= 1<<31 {
			return value.ErrUnavailable
		}
		// startsAt comes from the alert source's clock: a future time would
		// raise the watermark past later real alerts, so it counts as now.
		if started.After(now) {
			started = now
		}
		p := &pods[i]
		p.ProbeLast = max(p.ProbeLast, started.Unix())
		p.ProbeFailures = min(p.ProbeFailures+1, 1<<31)
	}
	return nil
}

func labelsMatch(labels, match map[string]string) bool {
	for k, v := range match {
		if labels[k] != v {
			return false
		}
	}
	return true
}
