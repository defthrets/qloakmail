FROM alpine:3.20

RUN apk add --no-cache tor && \
    install -d -o tor -g tor -m 0700 /var/lib/tor

COPY torrc /etc/tor/torrc
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER tor
CMD ["/entrypoint.sh"]
