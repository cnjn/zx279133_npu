#!/bin/sh
# Static ARM32 EABI5 soft-float build of zx-fwslot with the Bootlin musl
# toolchain used for BusyBox. The toolchain needs an x86-64 glibc host; on
# other hosts run this script inside e.g.
#   docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/w" -w /w \
#     debian:bookworm-slim sh build_zx_fwslot.sh
set -eu
cc=${CC:-build/busybox-toolchain/armv5-eabi--musl--stable-2024.05-1/bin/arm-linux-gcc}
mkdir -p build/zx-fwslot
"$cc" -std=c11 -Wall -Wextra -Werror -Os -static -s -o build/zx-fwslot/zx-fwslot zx_fwslot.c
