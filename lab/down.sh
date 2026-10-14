#!/usr/bin/env bash
# Tear down the test lab.
for p in flask php cors-reflect cors-null cors-wildcard deser origin403 \
         login-redirect deep-headers passive hostile spa; do
  docker rm -f "lab-${p}" >/dev/null 2>&1 && echo "down lab-${p}"
done
