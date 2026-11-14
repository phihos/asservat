package contracts

import (
	"fmt"
)

func releaseTestImage(n int) string {
	return fmt.Sprintf("registry.example.test:5000/asservat@sha256:%064x", n)
}
