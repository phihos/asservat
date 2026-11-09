package live

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
)

type Keys interface {
	LiveDigest(string, []byte) (artifact.Digest, error)
}

func (s *Service) account(domain string, value any) ([32]byte, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return [32]byte{}, fmt.Errorf("%w: cursor:21", v.ErrInvalid)
	}
	defer clear(b)
	d, e := s.cfg.Keys.LiveDigest(domain, b)
	return [32]byte(d), e
}
func (s *Service) cursorDigest(st *session, position uint64) (artifact.Digest, error) {
	b, e := json.Marshal(struct {
		ID, Fence            string
		Principal, Selection [32]byte
		Actor                identity.Principal
		Revision             int64
		Position             uint64
		OutputLimit          int64
	}{st.watch.ID, st.control.Fence, st.control.PrincipalKey, st.control.RequestDigest, st.actor, st.watch.Revision, position, st.control.OutputLimit})
	if e != nil {
		return artifact.Digest{}, e
	}
	defer clear(b)
	return s.cfg.Keys.LiveDigest("cursor", b)
}
func (s *Service) cursor(st *session) string {
	d, e := s.cursorDigest(st, st.position)
	if e != nil {
		return ""
	}
	return "live1." + strconv.FormatUint(st.position, 10) + "." + hex.EncodeToString(d[:])
}
func (s *Service) cursorPosition(st *session, cursor string) (uint64, bool) {
	p := strings.Split(cursor, ".")
	if len(p) != 3 || p[0] != "live1" || len(p[1]) > 20 || len(p[2]) != 64 {
		return 0, false
	}
	n, e := strconv.ParseUint(p[1], 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != p[1] {
		return 0, false
	}
	got, e := hex.DecodeString(p[2])
	if e != nil {
		return 0, false
	}
	expected, e := s.cursorDigest(st, n)
	return n, e == nil && subtle.ConstantTimeCompare(got, expected[:]) == 1
}
