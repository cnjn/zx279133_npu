#!/bin/sh
# Run on an x86-64 glibc host with an extracted Bootlin ARM musl cross compiler.
set -eu
if [ "$#" != 2 ]; then
    printf 'Usage: sh %s BUSYBOX_SOURCE_DIR ABSOLUTE_CROSS_PREFIX\n' "$0" >&2
    exit 2
fi
src=$1
cross=$2
case "$cross" in /*) ;; *) exit 2 ;; esac
cd "$src"
export LC_ALL=C
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1767225600}
make defconfig
python3 - <<'PY'
import re
from pathlib import Path

path = Path('.config')
config = path.read_text()
for name, value in {
    'STATIC': 'y',
    # Stock rcS does chmod 4755 /bin/busybox. Like the stock build, drop root for
    # applets run by non-root users; without this, e.g. a vendor `kill -9 -1` running
    # as csp kills every process on the stock system.
    'FEATURE_SUID': 'y',
    'FEATURE_SUID_CONFIG': 'y',
    'FEATURE_SUID_CONFIG_QUIET': 'y',
    'FEATURE_DEFAULT_PASSWD_ALGO': '"sha512"',
    'FEATURE_SEAMLESS_Z': 'y',
}.items():
    key = 'CONFIG_' + name
    line = f'# {key} is not set' if value is None else f'{key}={value}'
    config, count = re.subn(rf'^(?:{key}=.*|# {key} is not set)$', line, config, flags=re.M)
    if count != 1:
        raise SystemExit(f'Expected exactly one {key} in BusyBox defconfig')
path.write_text(config)
PY
make oldconfig </dev/null
make -j "${JOBS:-8}" CROSS_COMPILE="$cross"
