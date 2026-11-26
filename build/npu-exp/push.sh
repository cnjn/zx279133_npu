#!/bin/sh
# Usage (on the Mac): sh push.sh LOCALFILE REMOTE_PATH [PORT] -- send a file to the ONT over LAN.
f=$1; dst=$2; port=${3:-9123}; ser=/tmp/ontser.WZUED8/ser.py
python3 $ser "nc -l -p $port > $dst & sleep 1; echo listening" 10 >/dev/null
python3 -c "import socket,sys; s=socket.create_connection(('192.168.1.1',int(sys.argv[2]))); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$f" "$port"
sleep 1
echo "remote: $(python3 $ser "sha256sum $dst" 10 | head -1 | cut -c1-64)"
echo "local:  $(shasum -a 256 "$f" | cut -c1-64)"
