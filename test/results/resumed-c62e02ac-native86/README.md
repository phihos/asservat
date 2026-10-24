# native86 — poll cut by projection authority ValidUntil mid-read

`result/until-authority/prepare/read`; worker attached just after and found the
lease expired.

Cause (804ed07f): cached retention topology reading used to its last instant (proof observed 19:32:37.83, valid to 19:33:07.83).
