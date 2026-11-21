FROM docker.io/library/golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -o /asservat ./cmd/asservat

# One image serves the hub and the node agent. The agent runs the standard
# tools: nsenter (util-linux), tcpdump, gcore (gdb), strace and curl.
FROM docker.io/library/debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gdb strace tcpdump && rm -rf /var/lib/apt/lists/*
COPY --from=build /asservat /usr/local/bin/asservat
ENTRYPOINT ["/usr/local/bin/asservat"]
