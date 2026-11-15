package capture

import "unicode/utf8"

// ValidReason bounds the optional free-text capture reason. It is descriptive
// metadata stored in SQL with the capture (ADR-330 D8), never authority.
func ValidReason(text string) bool {
	n := utf8.RuneCountInString(text)
	return utf8.ValidString(text) && n > 0 && n <= 512
}
