# native72 — query worker enrollment refused after signing

First excerpt returned pending; worker Job ran; OpenBao signed two valid leaves
but the hub rejected its stored attempt (time.Time == with monotonic clock), both
signing attempts were spent and the worker exited after 30 s. Fixed in f8d30f4d.
