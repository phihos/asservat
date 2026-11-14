# Identity during a native response

C-02 contract for authenticating a native content GET under
[ADR-311](../decisions/311-operation-authority-recheck.md) and
[ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md).

A content GET resolves `CurrentIdentity` once, before the response starts:

- **Browser:** the session cookie is read with `allowRefresh=false`. GET never
  refreshes, creates or replaces a session
  ([ADR-224](../decisions/224-remove-download-refresh-owners.md)). If the
  session is busy because another request is refreshing it, the GET waits
  without output for that refresh, bounded only by the ordinary five-second
  I/O timeout (ADR-330 D5), and resolves once more.
- **Bearer (MCP/OAuth client):** the presented access token is validated as for
  any API request.

The authorization consumer (C-03) then authorizes the exact download with that
identity's current groups and denies. A raw evidence download charges its raw
grant pool for the selected range in the same start transaction.

The started response keeps that identity until the download's original
bounds: the download session deadline, `AccessUntil`, Stop and, for a browser,
the session's fixed expiry. A bearer download is not bounded by its access
token's expiry or group freshness: it runs to these bounds regardless of
access-token expiry ([ADR-335](../decisions/335-usable-by-default.md) D9). It
does not resolve identity again. Session revocation or logout reaches it as an
event and closes the stream; bytes already in transport buffers cannot be
recalled.

A download that outlives its bounds stops there; the client resumes with a new
authenticated GET and `Range` within the original download deadlines. Tokens, cookies and `CurrentIdentity` are never forwarded to readers
or connectors.
