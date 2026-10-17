#!/bin/bash
# ADR-197: capacity SQL suite with the new regional workload enrollment stage.
cd /home/phil/Projekte/asservat
d=test/results/adr197-custody-8
export GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp-claude
find internal test migrations charts scripts cmd go.mod go.sum -type f -not -path "test/results/*" -print0 | sort -z | xargs -0 sha256sum | sha256sum > $d/source-before.txt
/home/phil/.cache/asservat-build/spec-venv/bin/python scripts/test-custody.py --fleet --run '^TestCapacityProducerWithRealPostgres$' > $d/harness.out 2>&1
rc=$?
find internal test migrations charts scripts cmd go.mod go.sum -type f -not -path 'test/results/*' -print0 | sort -z | xargs -0 sha256sum | sha256sum > $d/source-after.txt
cp test/results/fleet.log $d/ 2>/dev/null
cp test/results/fleet-environment.json $d/environment.json 2>/dev/null
echo "exit=$rc" > $d/exit.txt
