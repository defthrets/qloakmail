FROM nginx:1.27-alpine

RUN apk add --no-cache gettext openssl

COPY conf.d/ /etc/nginx/conf.d/
COPY entrypoint.sh /docker-entrypoint.d/40-voidmail.sh
RUN chmod +x /docker-entrypoint.d/40-voidmail.sh
