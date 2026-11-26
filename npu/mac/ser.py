#!/usr/bin/env python3
"""Mac side: run one shell command on the ONT UART shell and print its output.
usage: python3 ser.py "CMD" [TIMEOUT_S]   (serial device: $NPU_SERIAL_DEV)

The command runs in a subshell between two random markers; output ends with
'[exit N]', or '[TIMEOUT, raw tail]' plus the last 600 characters seen.
Only one ser.py / board_reboot.py may use the serial port at a time."""
import os
import random
import re
import select
import sys
import termios
import time

dev = os.environ.get("NPU_SERIAL_DEV", "/dev/cu.usbmodem5B140649641")
cmd = sys.argv[1]
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 20
fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
a = termios.tcgetattr(fd)
a[0] = 0; a[1] = 0; a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL; a[3] = 0
a[4] = a[5] = termios.B115200
a[6][termios.VMIN] = 0; a[6][termios.VTIME] = 0
termios.tcsetattr(fd, termios.TCSANOW, a)
termios.tcflush(fd, termios.TCIOFLUSH)
tag = "M%06d" % random.randrange(10**6)
# The echoed input contains "TAG_B;" and "TAG_E $?", the real output "TAG_B\r\n" and "TAG_E <digits>".
line = "echo %s_B; ( %s ); echo %s_E $?\n" % (tag, cmd, tag)
for i in range(0, len(line), 32):          # the UART shell loses characters when fed too fast
    os.write(fd, line[i:i + 32].encode())
    time.sleep(0.02)
start = (tag + "_B\r\n").encode()
done = re.compile((tag + r"_E (\d+)\r?\n").encode())
buf, end, status = b"", time.time() + timeout, None
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            buf += os.read(fd, 65536)
        except BlockingIOError:
            pass
        i = buf.find(start)
        m = done.search(buf, i) if i >= 0 else None
        if m:
            status = m.group(1).decode()
            body = buf[i + len(start):m.start()]
            break
if status is None:
    text = buf.decode(errors="replace").replace("\r", "")
    sys.stdout.write("[TIMEOUT, raw tail]\n" + text[-600:] + "\n")
else:
    sys.stdout.write(body.decode(errors="replace").replace("\r", "") + "[exit " + status + "]\n")
