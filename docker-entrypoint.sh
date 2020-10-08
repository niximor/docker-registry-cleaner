#!/bin/sh

if [ ! -x "$1" ]; then
    exec /usr/bin/env python3 /app/docker-registry-cleaner.py "$@"
else
    exec "$@"
fi
