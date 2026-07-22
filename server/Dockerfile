FROM --platform=linux/amd64 rust:latest AS build-stage
WORKDIR /builds

RUN apt update -y
RUN apt upgrade -y

# The CI workflow unzips the platform artifact into ./release before this build,
# so the release directory (guard-server binary + frontend/_static + example) is
# copied straight in.
COPY ./release /builds/release

RUN adduser kube --disabled-login
RUN usermod -s /bin/rbash kube

# Run the application as kube user
USER kube
EXPOSE 8000
CMD ["/builds/release/guard-server"]
