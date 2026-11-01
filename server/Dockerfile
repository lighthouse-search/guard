FROM --platform=linux/amd64 ubuntu:26.04 AS runtime
WORKDIR /builds

# Runtime libraries the guard-server binary is dynamically linked against.
# libmysqlclient24 provides libmysqlclient.so.24 (diesel/mysqlclient-sys) and
# pulls in the matching OpenSSL runtime (libssl.so.3) as a dependency.
# ca-certificates provides the trust store for outbound TLS (OAuth, SMTP).
#
# The soname is tied to the Ubuntu release: 24.04 ships MySQL 8.0
# (libmysqlclient21), 26.04 ships MySQL 8.4 (libmysqlclient24). Because the
# Linux binary links the distro library rather than a vendored one, this base
# image and the runner that builds the binary must be the same Ubuntu release —
# rust.yml pins the linux-amd64 build to ubuntu-26.04 for exactly that reason.
# Bumping the version here means bumping it there too, or the container starts
# and immediately dies on a missing libmysqlclient.so.<n>.
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends \
        libmysqlclient24 \
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
