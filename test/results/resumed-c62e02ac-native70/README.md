# native70 — worker claim refused inside the shared SQL fence

`excerpt/worker-admission/claim`. The root admission window is
LEAST(capacity source 30 s, fleet trust 5 s, permission stream 5 s, ...), both
5 s observations refreshed by an overloaded hub-worker. Relaxing them to 30 s.
