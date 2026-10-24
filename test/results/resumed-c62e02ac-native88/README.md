# native88 — complete worker read; refused at final serve/close

All three unwraps (used_roles=7), decrypt, parse and frames succeeded; the hub
received the projection and refused at the closing acknowledgement.

Cause (fbc22f6b): sendCompleted required the completion proof to name the outer stream gate; HubOperation.finish proves the inner operation gate, so every final close through the hub-local/relay path was refused.
