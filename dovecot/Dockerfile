FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        dovecot-imapd dovecot-lmtpd dovecot-pgsql \
        ca-certificates gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY conf.d/ /etc/dovecot/conf.d/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    mkdir -p /var/mail && chown -R 5000:5000 /var/mail

EXPOSE 143 993 24
CMD ["/entrypoint.sh"]
