"""Run on the Mac: reboot the ONT over the serial console WITHOUT typing during boot
(any keystroke stops U-Boot's autoboot), wait for the shell prompt, then run lan1-up.
If the board is found at the U-Boot prompt '=> ', it is resumed with `run bootcmd`.
usage: python3 board_reboot.py [--no-reboot]"""
import os
import select
import sys
import termios
import time

DEV = os.environ.get('NPU_SERIAL_DEV', '/dev/cu.usbmodem5B140649641')
fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
a = termios.tcgetattr(fd)
a[0] = 0; a[1] = 0; a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL; a[3] = 0
a[4] = a[5] = termios.B115200
a[6][termios.VMIN] = 0; a[6][termios.VTIME] = 0
termios.tcsetattr(fd, termios.TCSANOW, a)
termios.tcflush(fd, termios.TCIOFLUSH)


def send(s):
    for i in range(0, len(s), 32):
        os.write(fd, s[i:i + 32].encode())
        time.sleep(0.02)


def wait_for(patterns, timeout):
    buf, end = b'', time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                buf += os.read(fd, 4096)
            except BlockingIOError:
                pass
            for p in patterns:
                if p.encode() in buf[-400:]:
                    return p, buf
    return None, buf


if '--no-reboot' not in sys.argv:
    send('sync; reboot\n')
else:
    send('\n')                    # already booted: just ask for a prompt
hit, buf = wait_for(['ont-shell:~ #', '=> '], 240)
if hit == '=> ':
    print('found U-Boot prompt; resuming boot')
    send('run bootcmd\n')
    hit, buf = wait_for(['ont-shell:~ #'], 240)
print('boot:', 'shell prompt' if hit else 'TIMEOUT', flush=True)
def quiet(seconds):
    """wait until the console has been silent for `seconds`"""
    last = time.time()
    while time.time() - last < seconds:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                if os.read(fd, 4096):
                    last = time.time()
            except BlockingIOError:
                pass


if hit:
    for attempt in range(2):
        quiet(5)
        send('\n')
        if not wait_for(['ont-shell:~ #'], 10)[0]:
            continue
        send('/debug/bin/lan1-up > /tmp/lan1up.log 2>&1; echo LAN1UP_DONE $?\n')
        hit, buf = wait_for(['LAN1UP_DONE 0', 'LAN1UP_DONE 1'], 240)
        print('lan1-up:', hit)
        if hit:
            break
