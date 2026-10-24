# native87 — worker read refused before any key unwrap

Hub `serve/result/read/refused`; worker stopped at read; used_roles=0.

Cause (503a4bf2): the hub hello read deadline (5 s from request arrival) was not reset after attaching the projection conversation; admission+command checks took ~5 s.
