#!/bin/sh

echo "Starting kippo in the background...\n"
cd $(dirname $0)
twistd -y kippo.tac -l log/kippo.log --pidfile kippo.pid

