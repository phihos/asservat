package integration

import (
	"context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// installedPolicyFixture is the first workload cluster's regional workload
// and the operator's hub access, recorded before its journey runs, for the
// ADR-228 policy focus (ASSERVAT_JOURNEY_FOCUS=policy).
type installedPolicyFixture struct {
	region                       kubernetes.Interface
	hub                          rest.Interface
	base                         string
	cluster, namespace, workload string
	binding                      map[string]any
}

var installedPolicyTarget *installedPolicyFixture

// installedPublisherSettled, when set by the installer journey, waits until
// the publisher runs on the current cluster catalog: a catalog change (a
// regional enrollment) restarts it within one 15 s tick, which would cost an
// incident capture with a short publication margin its deadline.
var installedPublisherSettled func(context.Context)
