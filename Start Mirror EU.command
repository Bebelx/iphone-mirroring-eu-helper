#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -x /usr/bin/python3 ]; then
    PYTHON=/usr/bin/python3
elif command -v python3 >/dev/null 2>&1; then
    PYTHON=$(command -v python3)
else
    echo "Python 3 was not found."
    printf "Press Return to close..."
    read answer
    exit 1
fi

"$PYTHON" "$SCRIPT_DIR/mirror_eu.py" menu
status=$?
printf "\nPress Return to close..."
read answer
exit "$status"
