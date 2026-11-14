# Native download interruption and explicit restart

## Start a new download

The browser action **Start a new download** stops the previous download and
prepares one new session for the same saved artifact. The browser file restarts
from the beginning; the console never appends to a browser-owned partial file.
Collection is not repeated and no approval step is added. Current evidence
rights, processing restrictions, retention and quota are checked as for any new
preparation.

The console keeps the old Stop idempotency key and the new preparation key in
its page state. It submits the new preparation only after Stop returns
`Cancelled` or `AlreadyTerminal` (or status shows a terminal state). An unknown
Stop reply is retried with its original key; an unknown preparation reply is
retried with the new preparation key. Status reads and GETs never create a
replacement session. The new session never extends an old session, grant or
evidence lifetime and can fail for lack of quota.

## Resume from a local client

An authenticated local client keeps the partial file length, artifact ID, strong
ETag and full SHA-256. To resume it requests the content path with `Range` from
its current length and `If-Match` set to the original ETag, preparing a fresh
session under current rights if the old one has ended. It appends only a 206
with the exact expected `Content-Range`; on 200, 412 or denial it leaves the
partial file untouched. It verifies the SHA-256 of the reconstructed file.

No JavaScript Blob assembly, redirect to object storage or background GET is
used.
