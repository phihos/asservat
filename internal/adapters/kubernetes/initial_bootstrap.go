package kubernetes

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
)

// InitialBootstrap is the trusted installation prelude. It cannot activate a
// database, manufacture recovery authority, or accept arbitrary object bodies.
// Every live method is bound to the original parent and joined by Close.
type InitialBootstrap struct {
	desired       contracts.InitialBootstrap
	config        *rest.Config
	api           rest.Interface
	root          context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	closed, busy  bool
	joined        sync.WaitGroup
	seedUID       string
	routedPrelude *contracts.InitialBootstrapPrelude
	probeToken    string
	probeUntil    time.Time
	proof         *configMapProtection
}
