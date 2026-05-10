FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        postfix postfix-pcre opendkim opendkim-tools \
        rsyslog ca-certificates curl gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY main.cf.tmpl /etc/postfix/main.cf.tmpl
COPY master.cf.tmpl /etc/postfix/master.cf.tmpl
COPY transport.pcre /etc/postfix/transport.pcre
COPY virtual-domains.tmpl /etc/postfix/virtual-domains.tmpl
COPY virtual-aliases.pcre /etc/postfix/virtual-aliases.pcre
COPY header_checks.pcre /etc/postfix/header_checks.pcre
COPY opendkim/opendkim.conf.tmpl /etc/opendkim/opendkim.conf.tmpl
COPY opendkim/TrustedHosts /etc/opendkim/TrustedHosts
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 587
CMD ["/entrypoint.sh"]
