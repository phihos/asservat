# Process component VM setup failure

Native42147216939 on signed `c79e9fd086409a36e2bce0d2455652bf9731af28` fails before the collector harness starts. The tshark apt install reaches its existing170-second command bound and exits124 while downloading libwireshark. The collector run step is skipped; no artifacts or native acquisition/source/cleanup report exists. The native job lasts249seconds; this is elapsed job duration, not a billed-minute claim.

The process-only branch checks strict JSON and process metadata, and has no PCAPNG/tshark/capinfos calls. Its workflow now omits only that unused installation step. All other suite predicates are compared unchanged; all process bounds/assertions and20-minute job ceiling remain. This is a setup correction, not a process source fix or qualification pass. A new guarded run is still required.
