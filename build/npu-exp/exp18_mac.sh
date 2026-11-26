# runs on the Mac
cd /tmp/ontser.WZUED8
S(){ python3 ser.py "$1" "${2:-20}"; }
drops(){ S "dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/drop_status; dmesg -c | awk '/illegal|rsp drop\(|busy|overflow|slice|flownum/{s[\$0~/illegal/?\"ill\":\$0~/rsp drop\(/?\"rsp\":\$0~/busy/?\"busy\":\$0~/overflow/?\"ovf\":\$0~/slice/?\"slice\":\"flow\"]+=\$NF} /rsp drop pc/{pc=\$NF} END{for(k in s) printf \"%s=%d \", k, s[k]; print \"pc=\" pc}'" 20 | head -1; }
for v in 0018000000000000 0018000000000020 0018000000000040 0018000000000000; do
  hi=${v%????????}; lo=${v#????????}
  S "echo d73 $hi $lo > /sys/devices/platform/np/ppu_debug/inst_set; echo set" 10 >/dev/null
  b=$(drops)
  r=$(ping -c 10 -i 0.1 -t 3 192.168.1.1 | grep -o '[0-9]* packets received')
  a=$(drops)
  echo "$v | $r | before: $b | after: $a"
done
S "dmesg -c >/dev/null; echo d73 > /sys/devices/platform/np/ppu_debug/inst_get; dmesg -c | grep -o 'inst[0-9]: 0x[0-9a-f]*'" 10
