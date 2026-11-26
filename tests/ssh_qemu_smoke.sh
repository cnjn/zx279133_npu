#!/bin/sh
# Host-side smoke test of build/lan-ssh under qemu-arm user mode, using the
# host OpenSSH client: key and password login, scp (SFTP and legacy -O), sftp.
# The ARM dropbear runs as the current user, listens on 127.0.0.1 only, and
# reads passwd/authorized_keys from a throwaway sysroot through qemu -L.
# Paths under /debug are mapped into that sysroot by a small host-side shell
# wrapper; on the board they are real.  Usage: sh tests/ssh_qemu_smoke.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
bins=$root/build/lan-ssh
port=${SMOKE_PORT:-22722}
t=$(mktemp -d /tmp/ssh-smoke.XXXXXX)
pid=
cleanup() { [ -z "$pid" ] || kill "$pid" 2>/dev/null || true; [ -n "${SMOKE_KEEP:-}" ] || rm -rf "$t"; }
trap cleanup EXIT INT TERM
s=$t/sysroot
mkdir -p "$s/etc" "$s/home/lab/.ssh" "$s/debug/bin" "$s/debug/libexec" "$t/keys"
chmod 700 "$s/home/lab" "$s/home/lab/.ssh"

# Host wrappers standing in for the board's /debug paths and login shell.
cat >"$s/debug/bin/scp" <<EOF
#!/bin/sh
exec qemu-arm "$bins/dropbearmulti" scp "\$@"
EOF
cat >"$s/debug/libexec/sftp-server" <<EOF
#!/bin/sh
exec qemu-arm "$bins/sftp-server" "\$@"
EOF
cat >"$t/shell" <<EOF
#!/bin/sh
[ "\$1" = -c ] || exit 99
PATH=\$(printf %s "\$PATH" | sed "s#/debug/#$s/debug/#g")
export PATH
exec /bin/sh -c "\$(printf %s "\$2" | sed "s#/debug/#$s/debug/#g")"
EOF
chmod 755 "$s/debug/bin/scp" "$s/debug/libexec/sftp-server" "$t/shell"

hash='$6$ontlab-133$i9C4/73EeFM2F2CsX0wXCDL8htOW4SeN8MdncrtFlimAB0UWf2AAm3RTZ3n0G1nmMXqy6vxeahjGO8s.R2QLE.'
# The board has no /etc/shells, so musl falls back to /bin/sh; list the wrapper here.
printf '%s\n' "$t/shell" >"$s/etc/shells"
# Home is a real host path: qemu -L does not translate musl's statx() lookups.
printf 'lab:%s:%s:%s::%s:%s\n' "$hash" "$(id -u)" "$(id -g)" "$s/home/lab" "$t/shell" >"$s/etc/passwd"
ssh-keygen -q -t ed25519 -N '' -f "$t/keys/client"
cp "$t/keys/client.pub" "$s/home/lab/.ssh/authorized_keys"
chmod 600 "$s/home/lab/.ssh/authorized_keys"

qemu-arm "$bins/dropbearmulti" dropbearkey -t ed25519 -f "$t/keys/host" >/dev/null
qemu-arm -L "$s" "$bins/dropbearmulti" dropbear -F -E -r "$t/keys/host" \
    -p "127.0.0.1:$port" -P "$t/dropbear.pid" 2>"$t/dropbear.log" &
pid=$!
sleep 2

o="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
key="$o -o BatchMode=yes -o PasswordAuthentication=no -i $t/keys/client"
fail() { echo "FAIL: $*" >&2; tail -20 "$t/dropbear.log" >&2; exit 1; }

[ "$(ssh $key -p "$port" lab@127.0.0.1 echo key-ok)" = key-ok ] || fail "key login"
echo "ok: public-key login and command"

printf '#!/bin/sh\necho root\n' >"$t/askpass"; chmod 700 "$t/askpass"
out=$(SSH_ASKPASS="$t/askpass" SSH_ASKPASS_REQUIRE=force ssh $o -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 -p "$port" lab@127.0.0.1 echo pw-ok </dev/null) || true
[ "$out" = pw-ok ] || fail "password login (lab password root)"
echo "ok: password login (SHA-512 crypt)"

head -c 300000 /dev/urandom >"$t/payload"
mkdir "$t/remote"
scp -q $key -P "$port" "$t/payload" "lab@127.0.0.1:$t/remote/sftp-mode" || fail "scp (SFTP mode)"
cmp "$t/payload" "$t/remote/sftp-mode" || fail "scp (SFTP mode) content"
echo "ok: scp upload via sftp-server"
scp -q -O $key -P "$port" "$t/payload" "lab@127.0.0.1:$t/remote/legacy" || fail "scp -O"
cmp "$t/payload" "$t/remote/legacy" || fail "scp -O content"
scp -q -O $key -P "$port" "lab@127.0.0.1:$t/remote/legacy" "$t/back" || fail "scp -O download"
cmp "$t/payload" "$t/back" || fail "scp -O download content"
echo "ok: scp -O upload/download via dropbear scp"
printf 'get %s %s\n' "$t/remote/sftp-mode" "$t/sftp-back" |
    sftp -q $key -P "$port" -b - lab@127.0.0.1 >/dev/null || fail sftp
cmp "$t/payload" "$t/sftp-back" || fail "sftp content"
echo "ok: sftp download"
echo "all smoke checks passed"
