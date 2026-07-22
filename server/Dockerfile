FROM --platform=linux/amd64 ubuntu:24.04 AS runtime
WORKDIR /builds

# Runtime libraries the guard-server binary is dynamically linked against.
# libmysqlclient21 provides libmysqlclient.so.21 (diesel/mysqlclient-sys) and
# pulls in the matching OpenSSL runtime (libssl.so.3) as a dependency.
# ca-certificates provides the trust store for outbound TLS (OAuth, SMTP).
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends \
        libmysqlclient21 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The CI workflow unzips the platform artifact into ./release before this build,
# so the release directory (guard-server binary + frontend/_static + example) is
# copied straight in.
COPY ./release /builds/release

RUN useradd --create-home --shell /bin/rbash kube

# Run the application as kube user
USER kube
EXPOSE 8000
CMD ["/builds/release/guard-server"]
