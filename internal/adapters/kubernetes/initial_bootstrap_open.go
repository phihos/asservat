package kubernetes

import (
	"errors"
)

// ErrInitialBootstrapMaterialRequired is returned only for a positively absent
// original seed after current administrator and namespace checks. It is not a
// generic retry classification and never means a lost existing seed is safe.
var ErrInitialBootstrapMaterialRequired = errors.New("initial bootstrap needs explicit private material")
