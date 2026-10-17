#!/bin/bash
# Full Go gate with source hashes before and after (source freeze check).
cd /home/phil/Projekte/asservat
d=test/results/adr193-go-check-2
h() { find cmd internal test scripts -type f \( -name '*.go' -o -name '*.py' -o -name '*.sql' -o -name '*.json' -o -name '*.yaml' \) -not -path 'test/results/*' -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1; }
echo "before=$(h)" > $d/source-hash.txt
export GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp-claude
make go-check PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python > $d/go-check.log 2>&1
rc=$?
echo "after=$(h)" >> $d/source-hash.txt
echo "exit=$rc" >> $d/go-check.log
echo "exit=$rc" > $d/exit.txt
