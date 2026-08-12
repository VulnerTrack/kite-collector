#!/bin/sh
set -eu

nmbd --foreground --no-process-group &
smbd --foreground --no-process-group &
exec python /app/windows_winrm.py
