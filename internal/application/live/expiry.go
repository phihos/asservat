package live

import (
	v "asservat.local/asservat/internal/domain/live"
	"time"
)

// Exactly one finite timer per watch erases managed replay at its original
// expiry even if the viewer disappears. This is not an authority refresh or
// source poll and cannot prolong the watch or an individual row.
func (s *Service) armLocked(st *session) {
	if st.timer != nil {
		st.timer.Stop()
	}
	end := minTime(st.watch.IdleUntil, st.watch.ExpiresAt)
	for _, p := range st.replay {
		end = minTime(end, p.until)
	}
	if v.Terminal(st.watch.State) {
		s.eraseDetails(st)
		st.timer = time.AfterFunc(max(time.Duration(0), end.Sub(s.cfg.Now())), func() { s.expireSession(st) })
		return
	}
	st.timer = time.AfterFunc(max(time.Duration(0), end.Sub(s.cfg.Now())), func() { s.expireSession(st) })
}
func (s *Service) eraseDetails(st *session) {
	clear(st.replay)
	st.replay = map[string]replay{}
	st.paid = nil
	clear(st.filter.All)
	st.filter.All = nil
	clear(st.selected)
	st.selected = nil
	st.positions = nil
	st.gap = nil
}
func (s *Service) expireSession(st *session) {
	st.mu.Lock()
	now := s.cfg.Now()
	for key, p := range st.replay {
		if !now.Before(p.until) {
			delete(st.replay, key)
		}
	}
	ended := !now.Before(st.watch.ExpiresAt) || !now.Before(st.watch.IdleUntil) || v.Terminal(st.watch.State)
	if ended {
		s.clear(st, "Expired")
		if st.cancelRead != nil {
			st.cancelRead()
		}
		joined := st.readJoined
		reading := st.reading
		st.mu.Unlock()
		if reading {
			<-joined
		}
		st.mu.Lock()
		s.eraseDetails(st)
	} else {
		s.armLocked(st)
	}
	st.mu.Unlock()
	if ended {
		s.mu.Lock()
		if s.sessions[st.watch.ID] == st {
			delete(s.sessions, st.watch.ID)
			for k, id := range s.opens {
				if id == st.watch.ID {
					delete(s.opens, k)
				}
			}
		}
		s.mu.Unlock()
	}
}

// Close belongs to the owning runtime, not a public close-view request.
// Locking joins any active timer callback before releasing private details.
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	all := make([]*session, 0, len(s.sessions))
	for _, st := range s.sessions {
		all = append(all, st)
	}
	clear(s.sessions)
	clear(s.opens)
	s.mu.Unlock()
	for _, st := range all {
		st.mu.Lock()
		if st.timer != nil {
			st.timer.Stop()
		}
		s.clear(st, "Closed")
		if st.cancelRead != nil {
			st.cancelRead()
		}
		joined := st.readJoined
		reading := st.reading
		st.mu.Unlock()
		if reading {
			<-joined
		}
		st.mu.Lock()
		s.eraseDetails(st)
		st.mu.Unlock()
	}
}
