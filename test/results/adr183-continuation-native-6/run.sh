#!/bin/bash
# ADR-183 native qualification: bootstrap chain -> actual installer-continue Pod + applier.
cd /home/phil/Projekte/asservat
d=test/results/adr183-continuation-native-6
export GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp-claude
/home/phil/.cache/asservat-build/spec-venv/bin/python scripts/test-context-storage.py --initial-bootstrap-chain --runtime-provider-pair --installer-continuation > $d/harness.out 2>&1
rc=$?
echo "exit=$rc" >> $d/harness.out
cp test/results/context-storage.log $d/ 2>/dev/null
cp test/results/context-storage-environment.json $d/environment.json 2>/dev/null
cp test/results/context-storage-kubelet.log $d/ 2>/dev/null
echo "exit=$rc" > $d/exit.txt
