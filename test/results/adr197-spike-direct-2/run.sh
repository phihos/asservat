#!/bin/bash
# ADR-197 spike part A: the direct v2 fixture with guard-then-workload in one five-second window, at injected
# regional owner-read latency (0, 100 ms, 250 ms). Measurement only.
cd /home/phil/Projekte/asservat
d=test/results/adr197-spike-direct-2
export GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp-claude
rm -f test/results/context-storage.log
find internal test migrations charts scripts cmd go.mod go.sum -type f -not -path "test/results/*" -print0 | sort -z | xargs -0 sha256sum | sha256sum > $d/source-before.txt
/home/phil/.cache/asservat-build/spec-venv/bin/python scripts/test-context-storage.py --run '^TestDirectHolderObservationWithRealKubernetes$' > $d/harness.out 2>&1
rc=$?
find internal test migrations charts scripts cmd go.mod go.sum -type f -not -path 'test/results/*' -print0 | sort -z | xargs -0 sha256sum | sha256sum > $d/source-after.txt
echo "exit=$rc" >> $d/harness.out
cp test/results/context-storage.log $d/ 2>/dev/null
cp test/results/context-storage-environment.json $d/environment.json 2>/dev/null
echo "exit=$rc" > $d/exit.txt
