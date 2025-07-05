FROM --platform=linux/amd64 rust:latest as build-stage
COPY /builds/oracularhades/release /builds/oracularhades/release
WORKDIR /builds/oracularhades/release

RUN apt update -y
RUN apt upgrade -y
RuN apt install tree
RUN tree /

RUN adduser kube --disabled-login
RUN usermod -s /bin/rbash kube

# Run the application as kube user
USER kube
EXPOSE 8000
CMD /builds/oracularhades/release/guard-server