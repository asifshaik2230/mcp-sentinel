#!/bin/sh
set -e
mkdir -p /data
chown -R sentinel:sentinel /data 2>/dev/null || true
exec gosu sentinel java $JAVA_OPTS -jar /app/app.jar
