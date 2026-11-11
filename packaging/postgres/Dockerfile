# Build from the same qualified PostgreSQL18 base used by the service fixtures.
FROM postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c AS backrest
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc meson ninja-build pkg-config python3-yaml ca-certificates curl \
    libssl-dev libxml2-dev libzstd-dev liblz4-dev libbz2-dev zlib1g-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*
# Upstream release/2.60.0, exact source commit and archive digest.
RUN curl --fail --location --proto '=https' --tlsv1.2 \
    https://codeload.github.com/pgbackrest/pgbackrest/tar.gz/2e1c4f2ba727c45a0a23d4b326905088dc15b1a1 \
    -o /tmp/pgbackrest.tar.gz \
    && echo 'cb66645c0d436d21dfa5697b2e124556f5fe94c71b792dea836472ff8dcde96a  /tmp/pgbackrest.tar.gz' | sha256sum -c - \
    && mkdir /src && tar -xzf /tmp/pgbackrest.tar.gz -C /src --strip-components=1 \
    && meson setup /src/build /src --prefix=/usr/local -Dlibssh2=disabled -Dlibsystemd=disabled \
    && ninja -C /src/build && meson install -C /src/build

FROM postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 liblz4-1 libzstd1 libbz2-1.0 \
    && rm -rf /var/lib/apt/lists/*
# COPY --chmod also applies to a newly created destination parent. Create this
# directory explicitly so read-only configuration remains traversable by999.
RUN install -d -m 0755 /etc/asservat
COPY --from=backrest /usr/local/bin/pgbackrest /usr/local/bin/pgbackrest
COPY --chmod=0555 packaging/postgres/entrypoint.sh /usr/local/bin/asservat-postgres
COPY --chmod=0444 packaging/postgres/postgresql.conf /etc/asservat/postgresql.conf
COPY --chmod=0444 packaging/postgres/pg_hba.conf /etc/asservat/pg_hba.conf
USER 999:999
ENTRYPOINT ["/usr/local/bin/asservat-postgres"]
CMD ["server"]
