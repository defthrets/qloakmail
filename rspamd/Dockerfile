FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        rspamd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY local.d/ /etc/rspamd/local.d/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 11332 11333 11334
CMD ["/entrypoint.sh"]
