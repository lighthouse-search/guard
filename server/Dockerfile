FROM --platform=linux/amd64 rust:latest as build-stage
WORKDIR /builds/oracularhades/release
EXPOSE 8000

RUN adduser kube --disabled-login
RUN usermod -s /bin/rbash kube

# Run the application as kube user
USER kube
CMD echo "defaults\nauth on\ntls on\ntls_starttls on\n\naccount smtp\nhost $smtp_host\nport $smtp_port\nfrom $smtp_from_header\nuser $smtp_username\npassword $smtp_password\n\n# Set default\naccount default : smtp" > /home/kube/.msmtprc && chmod 600 /home/kube/.msmtprc && ./target/release/guard-server