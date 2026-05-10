#!/bin/sh
set -eu

# On first boot, tor will create the hidden service directory and
# print the .onion address. Show it on every start so it's easy to
# discover via `docker compose logs tor`.

(
    while true; do
        if [ -f /var/lib/tor/voidmail/hostname ]; then
            echo "================================================================"
            echo "VoidMail .onion address:"
            cat /var/lib/tor/voidmail/hostname
            echo "================================================================"
            break
        fi
        sleep 2
    done
) &

exec tor -f /etc/tor/torrc
