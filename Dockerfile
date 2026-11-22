FROM docker.io/library/golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -o /asservat ./cmd/asservat
# Go's trace tool shows execution traces in the hub; "go tool trace" is not
# a program of its own, so it is built from the toolchain's source.
RUN CGO_ENABLED=0 go build -trimpath -o /gotrace cmd/trace

# One image serves the hub and the node agent. The agent runs the standard
# tools: nsenter (util-linux), tcpdump, gcore (gdb), strace and curl. The hub
# reads packet captures for their viewer with Wireshark's sharkd (tshark), and
# pprof draws its graph view with dot (graphviz).
FROM docker.io/library/debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gdb graphviz strace tcpdump tshark && rm -rf /var/lib/apt/lists/*
COPY --from=build /asservat /gotrace /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/asservat"]
