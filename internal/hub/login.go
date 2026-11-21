package hub

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Browser sign-in: the hub sends the browser to the OIDC provider
// (authorization code flow with PKCE), verifies the ID token it gets for the
// code and keeps the user's name and groups in a signed session cookie.

const (
	loginCookie   = "asservat_login"
	sessionCookie = "asservat_session"
	// sessionLifetime is how long a browser session lasts. Its groups are
	// those of the sign-in, so a new sign-in each working day keeps them
	// current.
	sessionLifetime = 12 * time.Hour
)

func (h *Hub) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(h.OAuth.RedirectURL, "https://")}
}

// loginInfo tells the console which ways to sign in exist.
func (h *Hub) loginInfo(w http.ResponseWriter, r *http.Request) {
	reply(w, map[string]bool{"oidc": h.OAuth != nil})
}

func (h *Hub) login(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		fail(w, err)
		return
	}
	state, verifier := base64.RawURLEncoding.EncodeToString(raw), oauth2.GenerateVerifier()
	// The callback must come from the browser that began the sign-in.
	http.SetCookie(w, h.cookie(loginCookie, state+"."+verifier, 600))
	http.Redirect(w, r, h.OAuth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (h *Hub) loginCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(loginCookie)
	if err != nil {
		fail(w, errStatus{http.StatusBadRequest, "no sign-in is in progress in this browser"})
		return
	}
	state, verifier, _ := strings.Cut(c.Value, ".")
	if subtle.ConstantTimeCompare([]byte(state), []byte(r.URL.Query().Get("state"))) != 1 {
		fail(w, errStatus{http.StatusBadRequest, "the sign-in does not match the one begun in this browser"})
		return
	}
	if msg := r.URL.Query().Get("error"); msg != "" {
		fail(w, errStatus{http.StatusForbidden, "the identity provider refused the sign-in: " + msg})
		return
	}
	token, err := h.OAuth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		fail(w, errStatus{http.StatusBadGateway, "the identity provider did not accept the sign-in code"})
		return
	}
	id, _ := token.Extra("id_token").(string)
	u, err := h.Verify(r.Context(), id)
	if err != nil {
		fail(w, errStatus{http.StatusForbidden, "the identity provider's token was not accepted: " + err.Error()})
		return
	}
	http.SetCookie(w, h.cookie(loginCookie, "", -1))
	http.SetCookie(w, h.cookie(sessionCookie, h.session(u, time.Now().Add(sessionLifetime)), int(sessionLifetime/time.Second)))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Hub) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, h.cookie(sessionCookie, "", -1))
}

type sessionClaims struct {
	Name    string   `json:"name"`
	Groups  []string `json:"groups"`
	Expires int64    `json:"exp"`
}

// sessionMAC authenticates a session with a key derived from the master key.
func (h *Hub) sessionMAC(payload string) []byte {
	key := hmac.New(sha256.New, h.MasterKey)
	key.Write([]byte("asservat browser session"))
	mac := hmac.New(sha256.New, key.Sum(nil))
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// session returns the cookie value for a signed-in user.
func (h *Hub) session(u User, expires time.Time) string {
	b, _ := json.Marshal(sessionClaims{u.Name, u.Groups, expires.Unix()})
	payload := base64.RawURLEncoding.EncodeToString(b)
	return payload + "." + base64.RawURLEncoding.EncodeToString(h.sessionMAC(payload))
}

// openSession returns the user of a session cookie value that this hub
// issued and that has not expired.
func (h *Hub) openSession(value string, now time.Time) (User, error) {
	payload, mac, _ := strings.Cut(value, ".")
	got, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil || !hmac.Equal(got, h.sessionMAC(payload)) {
		return User{}, errors.New("invalid session")
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	var c sessionClaims
	if err != nil || json.Unmarshal(b, &c) != nil || now.Unix() >= c.Expires {
		return User{}, errors.New("expired session")
	}
	return User{Name: c.Name, Groups: c.Groups}, nil
}
