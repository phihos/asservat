#!/usr/bin/env bash
# Build the pinned libpcap as a dependency-free static archive for the hub's
# filter compiler (ADR-243, S2). Only pcap_open_dead/pcap_compile are used, so
# every capture backend with extra libraries (D-Bus, RDMA, libnl, Bluetooth,
# USB, netmap, remote capture) is disabled. The tarball is checked against its
# recorded SHA-256 (the release signature was verified with the Tcpdump Group
# signing key E089DEF1D9C15D0D when the pin was recorded). Needs a C compiler,
# make, flex and bison; idempotent per prefix.
set -euo pipefail
version="${LIBPCAP_VERSION:?}"
sha256="${LIBPCAP_SHA256:?}"
prefix="${LIBPCAP_PREFIX:?}"
scratch="${TMPDIR:?}"
if [[ -f "$prefix/lib/libpcap.a" && -f "$prefix/include/pcap/pcap.h" ]]; then
  echo "libpcap $version already built in $prefix"
  exit 0
fi
work="$(mktemp -d "$scratch/libpcap.XXXXXX")"
trap 'rm -rf "$work"' EXIT
curl -fsSLo "$work/libpcap.tar.xz" "https://www.tcpdump.org/release/libpcap-$version.tar.xz"
echo "$sha256  $work/libpcap.tar.xz" | sha256sum -c -
tar -xJf "$work/libpcap.tar.xz" -C "$work"
cd "$work/libpcap-$version"
./configure --prefix="$prefix" --disable-shared --with-pcap=linux \
  --disable-dbus --disable-rdma --without-libnl --disable-bluetooth --disable-usb --disable-netmap --disable-remote >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
test -f "$prefix/lib/libpcap.a"
echo "libpcap $version built in $prefix"
