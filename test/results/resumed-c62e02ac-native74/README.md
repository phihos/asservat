# native74 — approved query poll refused at retention resolution

First excerpt pending, worker Job running; first poll refused at
`current/authority/retention` (retention_source 5 s window), so the worker was
never bound and its enrollment was refused at `identity`. Relaxing retention
source freshness to 30 s.
