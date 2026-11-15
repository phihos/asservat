package kms

// Runtime owns cancellation/join before releasing the cloned idle transport.
func (s *SigningKey) Close() {
	if s != nil && s.client != nil {
		s.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
}
