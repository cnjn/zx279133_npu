cd /tmp/ontser.WZUED8
echo "### before (stock microcode)"; python3 e69/udp_test.py
python3 ser.py "sh /tmp/e69/refl.apply; rm -f /tmp/td.txt; (tcpdump -i any -nn -c 50 udp port 7777 > /tmp/td.txt 2>&1 &); sleep 1; echo applied" 30 | grep applied
echo "### with reflector"; python3 e69/udp_test.py
echo "### ping with reflector"; ping -c 3 -i 0.3 192.168.1.1 | grep -o '[0-9]* packets received'
sleep 1
python3 ser.py "killall tcpdump; sleep 1; echo board-tcpdump:; cat /tmp/td.txt | grep -E 'captured|IP '; sh /tmp/e69/refl.restore >/dev/null; dmesg -c >/dev/null; echo 13b4 > /sys/devices/platform/np/ppu_debug/inst_get; dmesg -c | grep -o 'inst3: 0x[0-9a-f]*'" 30 | grep -v exit
echo "### after restore"; python3 e69/udp_test.py | tail -1
