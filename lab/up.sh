#!/usr/bin/env bash
# Bring up the Stack-Fingerprinter test lab: one container per persona,
# each published to 127.0.0.1:<port>. Image: lab-base (built via docker import).
set -u
LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG=lab-base:latest

# persona:port
PERSONAS=(
  "flask:8001" "php:8002" "cors-reflect:8003" "cors-null:8004"
  "cors-wildcard:8005" "deser:8006" "origin403:8007" "login-redirect:8008"
  "deep-headers:8009" "passive:8010" "hostile:8011" "spa:8012"
)

for entry in "${PERSONAS[@]}"; do
  persona="${entry%%:*}"; port="${entry##*:}"
  name="lab-${persona}"
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" \
    -e PERSONA="$persona" -e PORT=80 \
    -v "$LAB_DIR:/lab:ro" \
    -p "127.0.0.1:${port}:80" \
    "$IMG" python3 /lab/server.py >/dev/null \
    && echo "up  $name -> 127.0.0.1:${port}" \
    || echo "ERR $name"
done
