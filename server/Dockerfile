COPY /builds/oracularhades/release /guard-server

# Expose port 80 for the web server
EXPOSE 8000

# Remove libcap2-bin and clean up apt cache
RUN apt remove -y libcap2-bin
RUN apt autoremove -y
RUN apt clean

RUN adduser kube --disabled-login
RUN usermod -s /bin/rbash kube

# Run the application as kube user
USER kube
CMD echo "defaults\nauth on\ntls on\ntls_starttls on\n\naccount smtp\nhost $smtp_host\nport $smtp_port\nfrom $smtp_from_header\nuser $smtp_username\npassword $smtp_password\n\n# Set default\naccount default : smtp" > /home/kube/.msmtprc && chmod 600 /home/kube/.msmtprc && ./target/release/guard-server