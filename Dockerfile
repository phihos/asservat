# The base images are named by tag and by digest: the tag says which image
# is meant, the digest which one it is. An image that is built again under
# its tag then changes what runs on every node only with a commit here,
# which Dependabot proposes (.github/dependabot.yml).
FROM docker.io/library/golang:1.27@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
# Without symbol table and debug information (-s -w) the binary is 64 MB
# instead of 90 MB. Stack traces of a panic keep their functions and lines.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /asservat ./cmd/asservat
# Go's trace tool shows execution traces in the hub; "go tool trace" is not
# a program of its own, so it is built from the toolchain's source.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gotrace cmd/trace

# What the hub and the node agent both run: nsenter (util-linux), curl and,
# to describe a core dump, gdb (with gcore) and bsdtar and bsdcat
# (libarchive-tools) for the debug packages of distributions. The agent
# records with tcpdump and strace.
FROM docker.io/library/debian:stable-slim@sha256:a64d9dbf633e2a2503afac76be521dc25d9b5765150b30d31a3914d4ae969cab AS tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gdb libarchive-tools strace tcpdump && rm -rf /var/lib/apt/lists/*
# The C++ libraries of Alpine, which the .NET runtime for musl asks for.
FROM docker.io/library/alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS musl
RUN apk add --no-cache libstdc++ libgcc

# The node agent's image, which every node pulls: without the hub's viewers
# and without the tools that read the stacks of Python and .NET programs
# from a core dump, which the hub adds to the agent's description.
FROM tools AS agent
COPY --from=build /asservat /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/asservat"]

# The hub's image, the default: it reads packet captures for their viewer
# with Wireshark's sharkd (tshark), whose library alone is 130 MB, pprof
# draws its graph view with dot (graphviz), and it reads the stacks of Python
# and .NET programs from core dumps with pystack and dotnet-dump.
FROM tools
RUN apt-get update && apt-get install -y --no-install-recommends graphviz musl python3-venv tshark && rm -rf /var/lib/apt/lists/*
# pystack reads the Python stacks of a core dump for its description.
# pip is only needed to install it. The wheel is checked against its
# checksum, as the .NET downloads below are: this image holds the master key.
COPY internal/coredesc/pystack-requirements.txt /tmp/pystack-requirements.txt
RUN python3 -m venv /opt/pystack && /opt/pystack/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/pystack-requirements.txt && /opt/pystack/bin/pip uninstall -y pip && rm /tmp/pystack-requirements.txt
# dotnet-dump reads the managed stacks of a .NET core dump for its
# description. It needs a .NET runtime to run; both are in a directory that
# no image of a .NET program has its runtime in (internal/coredesc/dotnet.go).
# The checksums are those of the runtime's release metadata
# (builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json)
# and of the package in NuGet's catalog. Of the package only the tool is
# taken, with its native part for this processor.
#
# The helper library of a runtime that was built for musl, as in Alpine
# images, loads only into a tool that runs on musl. So the runtime is here
# a second time, built for musl, with the same tool beside it: its native
# part for musl under the name that the tool looks for, since the tool
# tells musl by Alpine's /etc/alpine-release. It runs with Debian's musl
# (the loader) and Alpine's C++ libraries.
ARG TARGETARCH
COPY --from=musl /usr/lib/libstdc++.so.6 /usr/lib/libgcc_s.so.1 /opt/asservat-dotnet-musl/lib/
RUN set -e; runtime=10.0.15; dump=10.0.750501; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) arch=x64; sum=a90177d75bc891f71aa814dde3bcf76a356f5a506824669f1891754457954a3d13b72f3ca04c98fa0fe588514a5a781f8a87b17930ee802105c14f9edb28318a; \
        musl=dca559d4265deac0a1f16f9f4e31a75f2210a71ff6f62b0131cf0dabdececca193c8a7eaf5a1bf4291b44b0afb13953b24ba1d8e58acd0bf80eb3f148c23594e;; \
      arm64) arch=arm64; sum=e2e8b907d9eb6c239cccf5c1fe67fd9a72c56fddccedca9ba41c8a53ff034293b335fdd9f7ab504f09bf7b3f165e0d14e34fc9ea1f06cc0e86d0dfb06d274b6a; \
        musl=847e3d3992148fa451f720a220776957c57641ddf2d7833eb9552ec266361e3c21f103867a6780796c50bbadbf8cec21c421d3bacd9f93da73d3b1e71f11b8af;; \
      *) echo "no .NET runtime is named here for this processor"; exit 1;; \
    esac; \
    mkdir -p /opt/asservat-dotnet/dump; cd /tmp; \
    curl -fsSL -o runtime.tar.gz "https://builds.dotnet.microsoft.com/dotnet/Runtime/$runtime/dotnet-runtime-$runtime-linux-$arch.tar.gz"; \
    echo "$sum  runtime.tar.gz" | sha512sum -c -; \
    tar -xzf runtime.tar.gz -C /opt/asservat-dotnet --no-same-owner; \
    curl -fsSL -o runtime.tar.gz "https://builds.dotnet.microsoft.com/dotnet/Runtime/$runtime/dotnet-runtime-$runtime-linux-musl-$arch.tar.gz"; \
    echo "$musl  runtime.tar.gz" | sha512sum -c -; \
    tar -xzf runtime.tar.gz -C /opt/asservat-dotnet-musl --no-same-owner; \
    curl -fsSL -o dump.zip "https://api.nuget.org/v3-flatcontainer/dotnet-dump/$dump/dotnet-dump.$dump.nupkg"; \
    echo "b5f977e8d1c9df381389e7e7e88cc5f5ecca9e9f3774187d437493f00bb3a07d02f5aa11df26abed44333b54771718ee56ddf6be3f828420e925f3e68090dd73  dump.zip" | sha512sum -c -; \
    bsdtar -xf dump.zip -C /opt/asservat-dotnet/dump --strip-components 3 --include "tools/net8.0/any/*"; \
    find /opt/asservat-dotnet/dump -mindepth 1 -maxdepth 1 -type d ! -name "linux-$arch" ! -name "linux-musl-$arch" -exec rm -r {} +; \
    cp -al /opt/asservat-dotnet/dump /opt/asservat-dotnet-musl/dump; \
    rm -r /opt/asservat-dotnet/dump/linux-musl-$arch /opt/asservat-dotnet-musl/dump/linux-$arch; \
    mv /opt/asservat-dotnet-musl/dump/linux-musl-$arch /opt/asservat-dotnet-musl/dump/linux-$arch; \
    rm runtime.tar.gz dump.zip
COPY --from=build /asservat /gotrace /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/asservat"]
