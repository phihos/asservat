package kubernetes

import (
	"net/http"
)

type initialMaterialRoundTrip func(*http.Request) (*http.Response, error)

func (f initialMaterialRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
