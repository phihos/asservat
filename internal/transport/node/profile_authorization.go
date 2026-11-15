package node

import (
	"bytes"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

// ReceivedWork is the only decoder that may consume a private authorization.
// The public queue decoder fails closed instead of silently dropping it.
func ReceivedWork(w contracts.NodeWork) (delivery.NodeWorkDelivery, bool) {
	var authorization []byte
	var unavailable bool
	if p := w.ProfileCapture; p != nil {
		hasValue := len(p.Authorization) > 0
		if p.AuthorizationRequired != (hasValue || p.AuthorizationUnavailable) || p.AuthorizationUnavailable && hasValue || hasValue && !execution.ValidGoProfileAuthorization(p.Authorization) {
			return delivery.NodeWorkDelivery{}, false
		}
		copy := *p
		authorization = bytes.Clone(copy.Authorization)
		unavailable = copy.AuthorizationUnavailable
		copy.Authorization = nil
		copy.AuthorizationUnavailable = false
		w.ProfileCapture = &copy
	}
	work, ok := DomainWork(w)
	if !ok || (len(authorization) > 0 || unavailable) && (work.Kind != collector.WorkProfileCapture || work.Profile == nil || !work.Profile.Valid()) {
		clear(authorization)
		return delivery.NodeWorkDelivery{}, false
	}
	return delivery.NodeWorkDelivery{Work: work, ProfileAuthorization: authorization, ProfileAuthorizationUnavailable: unavailable}, true
}
