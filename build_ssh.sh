#!/bin/sh
# Static ARM32 EABI5 soft-float Dropbear (multi: dropbear, dropbearkey, scp,
# dbclient) and OpenSSH sftp-server for the ZX279133 lab UART image.
# Inputs (hash-checked, extracted fresh): build/ssh-source/dropbear-2026.94.tar.bz2 and
# build/sftp-source/openssh-10.6p2.tar.gz. The Bootlin toolchain needs an
# x86-64 glibc host with make; on other hosts run inside e.g.
#   docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/w" -w /w \
#     sr1010-mesh-shim-builder-x86:cross sh build_ssh.sh
set -eu
root=$(pwd)
bin=$root/build/busybox-toolchain/armv5-eabi--musl--stable-2024.05-1/bin
host=arm-buildroot-linux-musleabi
export PATH="$bin:$PATH" LC_ALL=C SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1767225600}
out=$root/build/lan-ssh
work=$root/build/ssh-build
for d in "$out" "$work"; do
    [ ! -e "$d" ] || { echo "refusing to reuse $d" >&2; exit 1; }
done
(cd build/ssh-source && sha256sum -c dropbear-2026.94.tar.bz2.sha256)
(cd build/sftp-source && sha256sum -c openssh-10.6p2.tar.gz.sha256)
mkdir -p "$work/dropbear" "$work/openssh" "$out"

# Dropbear: out-of-tree, localoptions.h from the build directory.
# Python's bz2 instead of an external bzip2, which minimal build images lack.
python3 -c 'import bz2, sys; sys.stdout.buffer.write(bz2.open(sys.argv[1]).read())' \
    build/ssh-source/dropbear-2026.94.tar.bz2 | tar -x -C "$work"
cd "$work/dropbear"
cp "$root/ssh_localoptions.h" localoptions.h
CC=$host-gcc "$work/dropbear-2026.94/configure" --host=$host \
    --enable-static --disable-zlib --disable-pam --disable-lastlog \
    --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx \
    --disable-pututline --disable-pututxline >configure.log 2>&1
make -j "${JOBS:-8}" PROGRAMS="dropbear dropbearkey scp dbclient" MULTI=1 STATIC=1 >make.log 2>&1
$host-strip -o "$out/dropbearmulti" dropbearmulti

# OpenSSH: only sftp-server, no OpenSSL/zlib needed.
cd "$work/openssh"
tar -xzf "$root/build/sftp-source/openssh-10.6p2.tar.gz"
cd openssh-10.6p2
CC=$host-gcc LDFLAGS=-static ./configure --host=$host --without-openssl \
    --without-zlib --without-pam --without-selinux --without-kerberos5 \
    --without-libedit --without-security-key-builtin --disable-lastlog \
    --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx \
    --disable-pututline --disable-pututxline >configure.log 2>&1
make -j "${JOBS:-8}" sftp-server >make.log 2>&1
$host-strip -o "$out/sftp-server" sftp-server

cp "$root/build/lan1/lan1-register" "$out/lan1-register"
cd "$out" && sha256sum dropbearmulti sftp-server lan1-register > SHA256SUMS
cat SHA256SUMS
