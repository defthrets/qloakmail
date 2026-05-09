#!/bin/sh
# Render nginx config from envvars at container start.
set -eu
envsubst '${VOIDMAIL_DOMAIN}' < /etc/nginx/conf.d/voidmail.conf.template \
    > /etc/nginx/conf.d/voidmail.conf
rm -f /etc/nginx/conf.d/voidmail.conf.template
rm -f /etc/nginx/conf.d/default.conf || true
