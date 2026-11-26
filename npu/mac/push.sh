#!/bin/sh
# Mac side: send a file to the ONT over LAN and compare checksums.
# usage: sh push.sh LOCALFILE REMOTE_PATH [PORT]   (board IP: $NPU_BOARD_IP, default 192.168.1.1)
# Starts `nc -l` on the board through the serial console, then connects to it.
f=$1; dst=$2; port=${3:-9123}; here=$(cd "$(dirname "$0")" && pwd); ser=$here/ser.py
ip=${NPU_BOARD_IP:-192.168.1.1}
python3 $ser "nc -l -p $port > $dst & sleep 1; echo listening" 10 >/dev/null
python3 -c "import socket,sys; s=socket.create_connection((sys.argv[3],int(sys.argv[2])),timeout=20); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$f" "$port" "$ip"
sleep 1
echo "remote: $(python3 $ser "sha256sum $dst" 10 | head -1 | cut -c1-64)"
echo "local:  $(shasum -a 256 "$f" | cut -c1-64)"
