// Package audit coordinates durable intent/outcome publication.
package audit

import "errors"

var ErrUnavailable = errors.New("durable audit unavailable")
