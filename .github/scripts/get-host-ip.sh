#!/bin/sh

cat <<EOF | docker run --rm -i alpine:latest sh
apk add --no-cache iproute2 >/dev/null
ip -4 route show default | cut -d' ' -f3
EOF