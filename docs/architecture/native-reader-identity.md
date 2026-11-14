# Identity during a native response

C-02 contract for authenticating a native content GET under
[ADR-311](../decisions/311-operation-authority-recheck.md) and
[ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md).

A content GET resolves `CurrentIdentity` once, before the response starts:

- **Browser:** the session cookie is read with `allowRefresh=false`. GET never
  refreshes, creates or replaces a session
  ([ADR-224](../decisions/224-remove-download-refresh-owners.md)). If the
  session is busy because another request is refreshing it, the GET waits
  without output for at most two seconds and resolves once more.
- **Bearer (MCP/OAuth client):** the presented access token is validated as for
  any API request.

The authorization consumer (C-03) then authorizes the exact download with that
identity's current groups and denies. A raw evidence download charges its raw
grant pool for the selected range in the same start transaction.

The started response keeps that identity until its bound: the browser
session's fixed expiry, or the bearer token's expiry or group-freshness bound,
whichever applies, intersected with the session and access deadlines. It does
not resolve identity again. Session revocation or logout reaches it as an event
and closes the stream; bytes already in transport buffers cannot be recalled.

A long download that outlives its session or token stops there; the client
resumes with a new authenticated GET and `Range` within the original download
deadlines. Tokens, cookies and `CurrentIdentity` are never forwarded to readers
or connectors.
