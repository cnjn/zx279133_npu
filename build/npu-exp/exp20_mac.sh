cd /tmp/ontser.WZUED8
S(){ python3 ser.py "$1" "${2:-20}"; }
drops(){ S "dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/drop_status; dmesg -c | awk '/illegal/{i+=\$NF} /rsp drop\(/{r+=\$NF} /busy\(/{b+=\$NF} /overflow/{o+=\$NF} /slice/{s+=\$NF} /flownum/{f+=\$NF} /rsp drop pc/{pc=\$NF} END{printf \"ill=%d rsp=%d ovf=%d busy=%d flow=%d slice=%d pc=%s\", i,r,o,b,f,s,pc}'" 20 | head -1 | sed 's/\[exit 0\]//'; }
for v in 0018000000000040 0018000000000060 0018000000000080 00180000000000a0 00180000000000c0 00180000000000e0 0018000000000100 00180000000001e0 0018000601000003; do
  hi=${v%????????}; lo=${v#????????}
  S "echo 1 > /sys/devices/platform/np/ppu_debug/me_drop_reason_clr; echo d65 $hi $lo > /sys/devices/platform/np/ppu_debug/inst_set; echo set" 10 >/dev/null
  b=$(drops)
  r=$(ping -c 10 -i 0.1 -t 3 192.168.1.1 | grep -o '[0-9]* packets received')
  a=$(drops)
  echo "$v | $r | before: $b | after: $a"
done
S "echo 1 > /sys/devices/platform/np/ppu_debug/me_drop_reason_clr; dmesg -c >/dev/null; echo d65 > /sys/devices/platform/np/ppu_debug/inst_get; dmesg -c | grep -o 'inst1: 0x[0-9a-f]*'" 10
