# native79 — command to parked worker not written before poll deadline

Worker attached via parked request; ~11 identical fenced operation rechecks
before the command write exhausted the poll window (refused serve/command,
used_roles=0). Operation recheck reuse for 1 s (958444c5).
