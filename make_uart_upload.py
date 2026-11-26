#!/usr/bin/env python3
"""Wrap a trusted static ARM tool into a paste block for the UART lab shell."""

import argparse
import base64
import gzip
import hashlib
from pathlib import Path
import re

from build_debug_rootfs import require_static_arm


def paste_block(name, binary):
    require_static_arm(binary)
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', name):
        raise ValueError(f'Invalid tool name: {name!r}')
    var = name.replace('-', '_') + '_path'
    marker = name.upper().replace('-', '_') + '_PAYLOAD'
    packed = base64.encodebytes(gzip.compress(binary, mtime=0)).decode('ascii')
    digest = hashlib.sha256(binary).hexdigest()
    return f'''# Paste this block into the authorized UART shell with line pacing.
{var}=$(
    set -e
    umask 077
    d=$(/bin/busybox mktemp -d /tmp/{name}.XXXXXX)
    /bin/busybox base64 -d > "$d/{name}.gz" <<'{marker}'
{packed}{marker}
    /bin/busybox gzip -dc "$d/{name}.gz" > "$d/{name}"
    printf '%s  %s\\n' '{digest}' "$d/{name}" | /bin/busybox sha256sum -c - >&2
    /bin/busybox chmod 700 "$d/{name}"
    /bin/busybox rm "$d/{name}.gz"
    printf '%s\\n' "$d/{name}"
)
if [ -n "${var}" ]; then
    printf '{name} ready: %s\\n' "${var}"
else
    printf '{name} upload failed; do not run the decoded binary.\\n' >&2
fi
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name')
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path, help='new file; must not already exist')
    args = parser.parse_args()
    try:
        text = paste_block(args.name, args.binary.read_bytes())
        with args.output.open('x') as out:
            out.write(text)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'error: {exc}\n')
    print(f'{args.output}: {len(text.splitlines())} lines')


if __name__ == '__main__':
    main()
