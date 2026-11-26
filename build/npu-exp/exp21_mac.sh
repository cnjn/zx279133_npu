cd /tmp/ontser.WZUED8
S(){ python3 ser.py "$1" "${2:-20}"; }
K="dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/key_last_info; dmesg -c | grep -E 'key last|rsp last' | sed 's/ *: */ /' | awk '{print \$NF, \$0}' | cut -c1-70"
echo "== baseline (normal ping)"; ping -c 3 -i 0.2 192.168.1.1 >/dev/null; S "$K" 20
S "echo d67 18 20 > /sys/devices/platform/np/ppu_debug/inst_set; echo d66 18 9 > /sys/devices/platform/np/ppu_debug/inst_set; echo set" 10
echo "== ping with lkup 0x9 + drop"; ping -c 5 -i 0.2 -t 3 192.168.1.1 | grep -o '[0-9]* packets received'
S "$K" 20
S "echo d66 2906a76 66421 > /sys/devices/platform/np/ppu_debug/inst_set; echo d67 2986a2e 670e5 > /sys/devices/platform/np/ppu_debug/inst_set; dmesg -c >/dev/null; echo d64 > /sys/devices/platform/np/ppu_debug/inst_get; dmesg -c | grep -o 'inst[0-9]: 0x[0-9a-f]*'" 10
ping -c 3 -i 0.2 192.168.1.1 | grep -o '[0-9]* packets received'
