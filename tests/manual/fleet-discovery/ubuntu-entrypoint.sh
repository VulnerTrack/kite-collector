#!/bin/sh
set -eu

ssh-keygen -A
nmbd --foreground --no-process-group &
exec /usr/sbin/sshd -D -e
