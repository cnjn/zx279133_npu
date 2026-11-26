cd /tmp/ontser.WZUED8
S(){ python3 ser.py "$1" "${2:-20}"; }
cnt(){ S "dmesg -c >/dev/null; cat /sys/devices/platform/np/table_debug/debug_stat_show; dmesg -c | awk '/port id 15 output unicast/{u=\$NF} /port id 5 output unicast/{v=\$NF} END{print u+0, v+0}'" 20 | head -1; }
for v in orig nop orig; do
  if [ $v = nop ]; then S "echo d5e 0 0 > /sys/devices/platform/np/ppu_debug/inst_set; echo ok" 10 >/dev/null; fi
  if [ $v = orig ]; then S "echo d5e 178000 1f > /sys/devices/platform/np/ppu_debug/inst_set; echo ok" 10 >/dev/null; fi
  a=$(cnt); r=$(ping -c 10 -i 0.1 -t 3 192.168.1.1 | grep -o '[0-9]* packets received'); b=$(cnt)
  echo "$v | $r | p15/p5 before: $a after: $b"
done
S "dmesg -c >/dev/null; echo d5c > /sys/devices/platform/np/ppu_debug/inst_get; dmesg -c | grep -o 'inst[0-9]: 0x[0-9a-f]*'" 10
