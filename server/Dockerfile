# Use the official Rust image as the base
FROM --platform=linux/amd64 rust:latest as build-stage
WORKDIR /guard-server

LABEL org.opencontainers.image.source=https://github.com/oracularhades/guard

COPY Cargo.lock /guard-server/Cargo.lock
COPY Cargo.toml /guard-server/Cargo.toml
COPY README.md /guard-server/README.md
COPY src /guard-server/src
COPY frontend /guard-server/frontend

RUN apt update -y
RUN apt upgrade -y
RUN apt install -y curl git build-essential openssl libssl-dev libcap2-bin tree

# Create a non-root user to run Homebrew
RUN useradd -m -s /bin/bash linuxbrew && \
    mkdir -p /home/linuxbrew/.linuxbrew && \
    chown -R linuxbrew:linuxbrew /home/linuxbrew/.linuxbrew && \
    chown -R linuxbrew:linuxbrew /guard-server/* && \
    chown -R linuxbrew:linuxbrew /guard-server

RUN mkdir /guard-server-built
RUN mkdir /guard-server-built/frontend
RUN chown -R linuxbrew /guard-server-built

RUN chown -R linuxbrew /guard-server-built/frontend
RUN chown -R linuxbrew /guard-server

# Switch to the non-root user
USER linuxbrew
# Set environment variables for Homebrew
ENV PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:$PATH"

# I don't think this is needed.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
RUN brew install node

# Build front-end
WORKDIR /guard-server/frontend
RUN npm install
RUN npm run build

WORKDIR /guard-server

ENV PATH="/home/linuxbrew/.cargo/bin:${PATH}"

# Update crates
RUN cargo update
# Build
RUN cargo build --release

RUN mv /guard-server/target /guard-server-built/target
# Move into target/release for process relativity.
RUN mv /guard-server/frontend/_static /guard-server-built/target/release/frontend/_static
RUN tree /guard-server-built

WORKDIR /
USER root
RUN rm -rf /guard-server
RUN mv /guard-server-built /guard-server
WORKDIR /guard-server
USER linuxbrew

FROM --platform=linux/amd64 rust:latest as production-stage
WORKDIR /guard-server

# Install libcap2-bin for setting capabilities
RUN apt update
RUN apt upgrade -y
RUN apt install -y libcap2-bin default-mysql-client dnsutils

RUN which cargo
# Set the capability to bind to port 80 for the cargo binary
# RUN setcap 'cap_net_bind_service=+ep' /usr/local/cargo/bin/cargo

# Add a non-root user kube with restricted shell
RUN adduser kube --disabled-login
RUN usermod -s /bin/rbash kube

# RUN echo "defaults\nauth on\ntls on\ntls_starttls on\n\naccount smtp\nhost $smtp_host\nport $smtp_port\nfrom $smtp_from_header\nuser $smtp_username\npassword $smtp_password\n\n# Set default\naccount default : smtp" > /home/kube/.msmtprc
# RUN chown -R kube /home/kube/.msmtprc
# RUN chmod 600 /home/kube/.msmtprc

# RUN echo $smtp_password > /home/kube/.msmtp-password.gpg
# RUN chown -R kube /home/kube/.msmtp-password.gpg

COPY --from=build-stage /guard-server /guard-server

# Expose port 80 for the web server
EXPOSE 8000

# Remove libcap2-bin and clean up apt cache
RUN apt remove -y libcap2-bin
RUN apt autoremove -y
RUN apt clean

# Run the application as kube user
USER kube
CMD echo "defaults\nauth on\ntls on\ntls_starttls on\n\naccount smtp\nhost $smtp_host\nport $smtp_port\nfrom $smtp_from_header\nuser $smtp_username\npassword $smtp_password\n\n# Set default\naccount default : smtp" > /home/kube/.msmtprc && chmod 600 /home/kube/.msmtprc && ./target/release/guard-server