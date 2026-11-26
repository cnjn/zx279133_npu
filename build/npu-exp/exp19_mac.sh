cd /tmp/ontser.WZUED8
S(){ python3 ser.py "$1" "${2:-20}"; }
drops(){ S "dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/drop_status; dmesg -c | awk '/illegal/{i+=\$NF} /rsp drop\(/{r+=\$NF} /busy\(/{b+=\$NF} /overflow/{o+=\$NF} /slice/{s+=\$NF} /flownum/{f+=\$NF} END{printf \"ill=%d rsp=%d busy=%d ovf=%d slice=%d flow=%d\", i,r,b,o,s,f}'" 20 | head -1; }
for v in 0000000000000000 0018000000000040 0098000018000007 0098100018100007 02fa000800000007 0094000000000001 0088000000000000 0018000000000060 0018000601000003; do
  hi=${v%????????}; lo=${v#????????}
  S "echo d65 $hi $lo > /sys/devices/platform/np/ppu_debug/inst_set; echo set" 10 >/dev/null
  b=$(drops)
  r=$(ping -c 10 -i 0.1 -t 3 192.168.1.1 | grep -o '[0-9]* packets received')
  a=$(drops)
  echo "$v | $r | before: $b | after: $a"
done
S "dmesg -c >/dev/null; echo d65 > /sys/devices/platform/np/ppu_debug/inst_get; dmesg -c | grep -o 'inst[0-9]: 0x[0-9a-f]*'" 10
