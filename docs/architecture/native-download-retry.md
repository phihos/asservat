# Native download interruption and explicit restart

The browser action **Start a new download** stops the previous download and creates
one new transfer request for the same saved artifact. It restarts the browser file
from the beginning; it does not append bytes to a browser-owned partial file.
Collection is not repeated. Current evidence rights, processing, retention and
installation capacity are checked again without another approval step.

The controller retains the old cancellation key and the proposed new preparation
key within its existing page/session ownership. It submits no new preparation until
Stop returns the exact download's acknowledged restrictive Cancelled/AlreadyTerminal
receipt (or its permitted terminal metadata status). Audit pending in that receipt
means the restrictive SQL fence is already effective; it is not an unknown Stop.
An uncertain Stop retries only its original key. An uncertain new preparation
retries only the new preparation key, retaining the prior Stop key until positive
new admission. Status reads and native GET never create a replacement. Scope loss
cancels continuation; late replies cannot resume it.

All earlier reservations and emitted/uncertain bytes stay charged. New preparation
uses remaining accepted allocation/worker/key/audit backing and can fail for lack of
capacity. It never refills an old session, revives an old worker, changes an artifact
version or extends an earlier grant, session or evidence lifetime.

Authenticated local clients can retain the actual local partial-file length, the
original artifact ID, ETag and full SHA256, explicitly prepare a fresh session under
current covering rights, verify its native metadata and request its content path
with Range and the original strong If-Match. They must require 206 plus the exact
Content-Range before appending; never append 200, and leave the incomplete file intact
on 412 or denial. Verify the entire reconstructed SHA256. Server emitted-byte counters
are not proof of bytes present in a local file.

Two intentionally completed 206 ranges on one original session and recovery after
an actual broken connection are different qualifications. The original first-context
worker stops after an Uncertain conversation; local HTTP/source cleanup is not a
remote Joined receipt. Failed/unknown old work must remain charged and cannot be
presented as safely resumable solely because local owner rows were closed. Native
qualification must establish each claimed flow separately. No JavaScript file Blob,
redirect to storage or background GET preparation is introduced.

This staged change does not enable runtime services or prove installed SSO, browser
partial-file append, a complete local-save outcome, or large-artifact throughput.
