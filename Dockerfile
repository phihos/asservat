FROM docker.io/library/golang:1.27 AS build
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
FROM docker.io/library/debian:stable-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gdb libarchive-tools strace tcpdump && rm -rf /var/lib/apt/lists/*
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
RUN apt-get update && apt-get install -y --no-install-recommends graphviz python3-venv tshark && rm -rf /var/lib/apt/lists/*
# pystack reads the Python stacks of a core dump for its description.
# pip is only needed to install it.
RUN python3 -m venv /opt/pystack && /opt/pystack/bin/pip install --no-cache-dir pystack==1.7.2 && /opt/pystack/bin/pip uninstall -y pip
# dotnet-dump reads the managed stacks of a .NET core dump for its
# description. It needs a .NET runtime to run; both are in a directory that
# no image of a .NET program has its runtime in (internal/coredesc/dotnet.go).
# The checksums are those of the runtime's release metadata
# (builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json)
# and of the package in NuGet's catalog. Of the package only the tool is
# taken, with its native part for this processor.
ARG TARGETARCH
RUN set -e; runtime=10.0.15; dump=10.0.750501; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) arch=x64; sum=a90177d75bc891f71aa814dde3bcf76a356f5a506824669f1891754457954a3d13b72f3ca04c98fa0fe588514a5a781f8a87b17930ee802105c14f9edb28318a;; \
      arm64) arch=arm64; sum=e2e8b907d9eb6c239cccf5c1fe67fd9a72c56fddccedca9ba41c8a53ff034293b335fdd9f7ab504f09bf7b3f165e0d14e34fc9ea1f06cc0e86d0dfb06d274b6a;; \
      *) echo "no .NET runtime is named here for this processor"; exit 1;; \
    esac; \
    mkdir -p /opt/asservat-dotnet/dump; cd /tmp; \
    curl -fsSL -o runtime.tar.gz "https://builds.dotnet.microsoft.com/dotnet/Runtime/$runtime/dotnet-runtime-$runtime-linux-$arch.tar.gz"; \
    echo "$sum  runtime.tar.gz" | sha512sum -c -; \
    tar -xzf runtime.tar.gz -C /opt/asservat-dotnet --no-same-owner; \
    curl -fsSL -o dump.zip "https://api.nuget.org/v3-flatcontainer/dotnet-dump/$dump/dotnet-dump.$dump.nupkg"; \
    echo "b5f977e8d1c9df381389e7e7e88cc5f5ecca9e9f3774187d437493f00bb3a07d02f5aa11df26abed44333b54771718ee56ddf6be3f828420e925f3e68090dd73  dump.zip" | sha512sum -c -; \
    bsdtar -xf dump.zip -C /opt/asservat-dotnet/dump --strip-components 3 --include "tools/net8.0/any/*"; \
    find /opt/asservat-dotnet/dump -mindepth 1 -maxdepth 1 -type d ! -name "linux-$arch" -exec rm -r {} +; \
    rm runtime.tar.gz dump.zip
COPY --from=build /asservat /gotrace /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/asservat"]
