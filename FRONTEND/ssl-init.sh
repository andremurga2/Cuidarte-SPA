#!/bin/sh
set -e
if [ ! -f /etc/nginx/ssl/cuidarteplus.key ]; then
  mkdir -p /etc/nginx/ssl
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/cuidarteplus.key -out /etc/nginx/ssl/cuidarteplus.crt \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  chmod 600 /etc/nginx/ssl/cuidarteplus.key
fi