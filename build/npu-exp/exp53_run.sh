# on the Mac. plan lines: TAG PC:WORD ... (last entry is the live hook, written last)
cd /tmp/ontser.WZUED8
P=/sys/devices/platform/np/ppu_debug/inst_set
wr(){ cmd=""; for pw in "$@"; do pc=${pw%%:*}; w=${pw#*:}; cmd="$cmd echo $(printf %x $pc) ${w%????????} ${w#????????} > $P;"; done; python3 ser.py "$cmd echo ok" 20 | grep -q ok; }
restore(){ set -- $(cat orig53.txt); n=$#; last=$(eval echo \${$n}); hook=$last; rest=""; i=1; for pw in "$@"; do [ $i -lt $n ] && rest="$rest $pw"; i=$((i+1)); done; wr $hook $rest; }
while read tag words; do
  wr $words || { echo "$tag apply-failed"; break; }
  n=$(ping -c 3 -i 0.2 -t 2 192.168.1.1 | grep -o '[0-9]* packets received' | cut -d' ' -f1)
  echo "$tag $n"
  restore; ping -c 2 -i 0.3 192.168.1.1 >/dev/null 2>&1
done < plan53.txt
restore
python3 ser.py "dmesg -c >/dev/null; for g in df0 df4 130c; do echo \$g > /sys/devices/platform/np/ppu_debug/inst_get; done; dmesg -c | grep -o 'inst[0-9]: 0x[0-9a-f]*'" 15
ping -c 3 -i 0.2 192.168.1.1 | grep -o '[0-9]* packets received'
