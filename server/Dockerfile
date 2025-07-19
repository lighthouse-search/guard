FROM --platform=linux/amd64 rust:latest as build-stage
WORKDIR /builds

RUN apt update -y
RUN apt upgrade -y
RUN apt install -y unzip tree

COPY ./guard.zip /builds/guard.zip
RUN tree /builds
RUN unzip /builds/guard.zip -d /builds/release
RUN tree /

RUN adduser kube --disabled-login
RUN usermod -s /bin/rbash kube

# Run the application as kube user
USER kube
EXPOSE 8000
CMD /builds/release/guard-server