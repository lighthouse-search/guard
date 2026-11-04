FROM --platform=linux/amd64 debian:trixie-slim AS runtime
WORKDIR /builds

# Runtime libraries the guard-server binary is dynamically linked against.
# libmariadb3 provides libmariadb.so.3 (diesel/mysqlclient-sys) — Debian ships
# MariaDB Connector/C as its MySQL client library, not Oracle's libmysqlclient —
# and pulls in the matching OpenSSL runtime (libssl.so.3) as a dependency.
# ca-certificates provides the trust store for outbound TLS (OAuth, SMTP).
#
# Because the Linux binary links the distro library rather than a vendored one,
# this base image and the container that builds the binary must be the same
# Debian release — rust.yml builds linux-amd64 inside debian:trixie for exactly
# that reason (it also sets the glibc floor). Bumping the release here means
# bumping it there too, or the container starts and immediately dies on a
# missing shared library.
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends \
        libmariadb3 \
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
