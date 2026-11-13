package kubernetes

import "errors"

var ErrSeaweedProvider = errors.New("bundled object store provider unavailable")

type seaweedProviderFailure string

func (e seaweedProviderFailure) Error() string     { return ErrSeaweedProvider.Error() }
func (e seaweedProviderFailure) Unwrap() error     { return ErrSeaweedProvider }
func (e seaweedProviderFailure) FixedStep() string { return string(e) }
