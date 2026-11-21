# ADR-172 — Authenticate the hub owner reached by a regional connector

Status: accepted. Applies to REQ-FED-001/003 and the S-02 regional context start.

A work notification identifies the exact hub owner that requested an exchange.
The connector opens a tunnel for that identity. The federation resolves its
current route. The connector then verifies the owner's TLS server name and
certificate over the tunnel. [Connector work delivery](334-connector-workload-identity.md).

The connector presents the certificate from that session to the federation's
`owner-authentication` endpoint. The hub checks the owner's current registration
and route and returns the verified certificate and configuration. The connector
verifies its original TLS session against that configuration and requires the
same certificate. Revocation, a stale route, or a different owner prevents the
exchange. Hub database credentials stay in the hub.
