package contracts

import (
	"time"
)

type InitialPreparationProbeResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}
