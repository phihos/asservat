package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const regionalStartDiscoveryBytes = 64 << 10

type regionalStartDiscoveryTransport struct{ http.RoundTripper }

func (t regionalStartDiscoveryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(r)
	if response != nil && response.Body != nil {
		// Stream decodes non-2xx bodies internally; cap those before client-go
		// reads them as well as bounding the successful discovery response.
		response.Body = &boundedBody{response.Body, regionalStartDiscoveryBytes + 1}
	}
	return response, err
}

// regionalStartAPIAvailable checks the operator-installed served API before
// the regional installer creates anything. Discovery neither qualifies the CRD
// schema nor supplies execution authority, and this reader never owns a CRD.
func regionalStartAPIAvailable(ctx context.Context, config *rest.Config) error {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	until, _ := call.Deadline()
	c := rest.CopyConfig(config)
	c.Wrap(func(t http.RoundTripper) http.RoundTripper { return regionalStartDiscoveryTransport{t} })
	api, err := newBoundedAPI(c)
	if err != nil {
		return cfg.ErrUnavailable
	}
	body, err := api.Get().AbsPath("/apis/asservat.io/v1alpha1").MaxRetries(0).Stream(call)
	if err != nil {
		return cfg.ErrUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, regionalStartDiscoveryBytes+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || len(raw) > regionalStartDiscoveryBytes ||
		call.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	var resources meta.APIResourceList
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&resources) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		resources.APIVersion != "v1" || resources.Kind != "APIResourceList" ||
		resources.GroupVersion != "asservat.io/v1alpha1" || len(resources.APIResources) > 256 {
		return cfg.ErrUnavailable
	}
	main, status := false, false
	for _, resource := range resources.APIResources {
		if resource.Name != "capacityreservations" && resource.Name != "capacityreservations/status" {
			continue
		}
		if !resource.Namespaced || resource.Kind != "CapacityReservation" ||
			resource.Group != "" && resource.Group != "asservat.io" ||
			resource.Version != "" && resource.Version != "v1alpha1" {
			return cfg.ErrUnavailable
		}
		if resource.Name == "capacityreservations" {
			if main || !slices.Contains(resource.Verbs, "get") || !slices.Contains(resource.Verbs, "create") {
				return cfg.ErrUnavailable
			}
			main = true
		} else {
			if status || !slices.Contains(resource.Verbs, "update") {
				return cfg.ErrUnavailable
			}
			status = true
		}
	}
	if !main || !status || call.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}
