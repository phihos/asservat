package kubernetes

import (
	"k8s.io/apimachinery/pkg/runtime"
)

type initialPreparationResource struct {
	object    runtime.Object
	path      string
	namespace string
	digest    string
}
