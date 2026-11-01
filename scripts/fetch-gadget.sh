#!/usr/bin/env bash
# ADR-248: fetch an Inspektor Gadget published gadget (tcpdump, traceloop), pinned by
# digest, as the four OCI blobs the collector loads from its image (index,
# linux/amd64 manifest, gadget config, eBPF program). Every blob is checked
# against its pinned SHA-256; nothing is pulled at runtime.
#   fetch-gadget.sh OUTDIR [tcpdump|traceloop]   writes OUTDIR/blobs/sha256/<hex>
set -euo pipefail
out=${1:?output directory}
gadget=${2:-tcpdump}
case $gadget in
tcpdump)
  repo=inspektor-gadget/gadget/tcpdump
  # v0.57.0 (gadget builder v0.57.0, created 2026-10-05). Keep in sync with
  # internal/adapters/gadget/tcpdump.go.
  blobs=(
    2176a5bd659841ad7bdbed1633a52b744ccb4232f3fd567e2388361ddd8e047a # index
    38d9bd068b4ddd3276dce72ea87f57b2716eac64adcbe64a65edb45fa3906981 # linux/amd64 manifest
    6379a2273c831a836cdcd0fcf362dfe1c6d90a474944d24f1e909375b4a6e84c # config (gadget.yaml)
    1e492d7cf4ca1f91cc16ff4e74d3d06d70844780366d09612244c5a08f6ad5f2 # eBPF program
  )
  ;;
traceloop)
  repo=inspektor-gadget/gadget/traceloop
  # v0.57.0. Keep in sync with internal/adapters/gadget/traceloop.go. The
  # wasm layer is deliberately not fetched: without it no syscall argument
  # definitions exist and the eBPF program never reads user memory.
  blobs=(
    e06e1c5f1397780162a91241771bd5833831dd6d7ec075e3bda6985404f97626 # index
    7779c72c24ec9f1023ec837cc3caf7492396b2e5be29d71e06331d44c08bace6 # linux/amd64 manifest
    491c5f695113c3d2c5f5a4ea2897f631cffe8789c0434ac0df40f03189e54b74 # config (gadget.yaml)
    49f885dd5bd0c6399efb1ead3971fa264558b5c3b81c2686486ab90f21841a73 # eBPF program
  )
  ;;
*) echo "unknown gadget $gadget" >&2; exit 2 ;;
esac
mkdir -p "$out/blobs/sha256"
have=1
for d in "${blobs[@]}"; do
  f="$out/blobs/sha256/$d"
  if [[ ! -s $f ]] || [[ $(sha256sum "$f" | cut -d' ' -f1) != "$d" ]]; then have=0; fi
done
[[ $have == 1 ]] && exit 0
token=$(curl -fsS "https://ghcr.io/token?scope=repository:$repo:pull" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
accept="application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"
for i in "${!blobs[@]}"; do
  d=${blobs[$i]}
  f="$out/blobs/sha256/$d"
  if (( i < 2 )); then url="https://ghcr.io/v2/$repo/manifests/sha256:$d"; else url="https://ghcr.io/v2/$repo/blobs/sha256:$d"; fi
  curl -fsSL -H "Authorization: Bearer $token" -H "Accept: $accept" -o "$f.tmp" "$url"
  got=$(sha256sum "$f.tmp" | cut -d' ' -f1)
  if [[ $got != "$d" ]]; then rm -f "$f.tmp"; echo "gadget blob digest mismatch: want $d got $got" >&2; exit 1; fi
  mv "$f.tmp" "$f"
done
