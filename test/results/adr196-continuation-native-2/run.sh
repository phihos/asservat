#!/bin/bash
# ADR-196 steps 4-5 (regional executor layout, join record, join command, hub-api catalog restart) + ADR-198 key service,
# actual installer-continue Pod + applier with public material), two clusters.
cd /home/phil/Projekte/asservat
d=test/results/adr196-continuation-native-2
export GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp-claude
rm -f test/results/context-storage.log
find internal test migrations charts scripts cmd go.mod go.sum -type f -not -path "test/results/*" -print0 | sort -z | xargs -0 sha256sum | sha256sum > $d/source-before.txt
/home/phil/.cache/asservat-build/spec-venv/bin/python scripts/test-context-storage.py --initial-bootstrap-chain --runtime-provider-pair --installer-continuation > $d/harness.out 2>&1
rc=$?
find internal test migrations charts scripts cmd go.mod go.sum -type f -not -path 'test/results/*' -print0 | sort -z | xargs -0 sha256sum | sha256sum > $d/source-after.txt
echo "exit=$rc" >> $d/harness.out
cp test/results/context-storage.log $d/ 2>/dev/null
cp test/results/context-storage-environment.json $d/environment.json 2>/dev/null
cp test/results/context-storage-kubelet.log $d/ 2>/dev/null
echo "exit=$rc" > $d/exit.txt
