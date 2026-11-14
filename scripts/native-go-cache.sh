#!/usr/bin/env bash
# native-go-cache.sh installed|race|collector
#
# Trim a restored full Go cache to what one kind of native suite builds
# (.github/workflows/native.yml restores it as go-native-<kind>-*):
#   installed  continuation-* (test package without -race, hub and collector images)
#   race       component suites (test package with -race, hub image, fixtures)
#   collector  collector-* (test package with the libpcap tag, collector image)
# The unit-test race builds of every package and the tool modules stay out.
#
# Go bumps the mtime of each build-cache entry it reads when that mtime is
# older than one hour. Backdate everything, run the builds the harnesses run
# (scripts/test-context-storage.py, test-custody.py, test-collector.py and the
# Makefile integration targets), then delete what no build touched. A build
# missing here only compiles in its native job, as on any cache miss.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo "CI only: it deletes most of this machine's Go caches" >&2; exit 2; }
kind=${1:?installed, race or collector}
cache=$(go env GOCACHE)
tmp=${ASSERVAT_BUILD_TMP:-$HOME/.cache/asservat-build/tmp}
mkdir -p "$tmp"
export TMPDIR=$tmp
du -sh "$cache" "$(go env GOMODCACHE)" || true
find "$cache" -type f -exec touch -d '2 hours ago' {} +

fixture=(env CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /dev/null)
collector_image() { "${fixture[@]}" -tags gadget,netgo,osusergo ./cmd/asservat; }
hub_image() {
  make --no-print-directory hub-binary HUB_BINARY="$tmp/native-cache-hub"
  rm -f "$tmp/native-cache-hub"
  "${fixture[@]}" ./test/fixtures/provider-proxy/main.go
}
builds() {
  "${fixture[@]}" ./test/fixtures/profile-native/main.go
  case $kind in
    installed)
      go test -count=1 -run '^$' ./test/integration >/dev/null
      hub_image
      collector_image
      "${fixture[@]}" ./test/fixtures/worker-resource-probe/main.go
      ;;
    race)
      go test -race -count=1 -run '^$' ./test/integration >/dev/null
      go test -c -o /dev/null ./internal/adapters/objectstore
      hub_image
      ;;
    collector)
      local pcap=$HOME/.cache/asservat-build/libpcap-1.11.0  # as scripts/test-collector.py
      make --no-print-directory libpcap >/dev/null
      CGO_ENABLED=1 CGO_CFLAGS="-I$pcap/include" CGO_LDFLAGS="-L$pcap/lib" \
        go test -tags libpcap -count=1 -run '^$' ./test/integration >/dev/null
      collector_image
      ;;
    *) echo "unknown kind $kind" >&2; exit 2 ;;
  esac
}
builds
find "$cache" -type f -mmin +60 -delete

# Module sources: only the main module's requirements, without the zips the
# extracted directories duplicate. GOPROXY=off below proves nothing is missing.
mods=$(go env GOMODCACHE)
fresh=$tmp/native-modcache
GOMODCACHE=$fresh go clean -modcache
GOMODCACHE=$fresh GOPROXY=file://$mods/cache/download,https://proxy.golang.org go mod download
go clean -modcache
chmod -R u+w "$mods" 2>/dev/null || true
rm -rf "$mods"
mv "$fresh" "$mods"
find "$mods/cache/download" -name '*.zip' -delete
GOPROXY=off builds
du -sh "$cache" "$mods"
