# native84 — worker gate hub check denied

Read attached; hub refused at `admission/gate/check/hub (denied)` with time left.

Cause (0c17ccbf): request identity KeyUntil from a one-minute JWKS snapshot used to its last instant cut the poll 1.36 s after it started; the gate hub check ran 31 ms before that end.
