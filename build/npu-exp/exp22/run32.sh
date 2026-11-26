# on the Mac: sh run.sh  (plan.txt, orig.txt alongside)
cd /tmp/ontser.WZUED8
P=/sys/devices/platform/np/ppu_debug/inst_set
apply(){ # 13 words for PC 3430..3442; entry word 3430 written last
  set -- "$@"; cmd=""; pc=3431; shift_first=$1; shift
  for w in "$@"; do cmd="$cmd echo $(printf %x $pc) ${w%????????} ${w#????????} > $P;"; pc=$((pc+1)); done
  cmd="$cmd echo d66 ${shift_first%????????} ${shift_first#????????} > $P; echo ok"
  python3 ser.py "$cmd" 15 | grep -q ok
}
restore(){ set -- $(cat orig.txt); first=$1; shift
  cmd="echo d66 ${first%????????} ${first#????????} > $P;"; pc=3431
  for w in "$@"; do cmd="$cmd echo $(printf %x $pc) ${w%????????} ${w#????????} > $P;"; pc=$((pc+1)); done
  python3 ser.py "$cmd echo restored" 15 | head -1; }
while read tag words; do
  apply $words || { echo "$tag apply-failed"; break; }
  n=$(ping -c 3 -i 0.2 -t 2 192.168.1.1 | grep -o '[0-9]* packets received' | cut -d' ' -f1)
  echo "$tag $n"
  restore >/dev/null; ping -c 2 -i 0.3 192.168.1.1 >/dev/null 2>&1
  if [ "$tag" = k0b-2 ] && [ "$n" = 0 ]; then echo "control failed, abort"; break; fi
done < plan32.txt
restore
python3 ser.py "dmesg -c >/dev/null; for g in d64 d68 d6c d70; do echo \$g > /sys/devices/platform/np/ppu_debug/inst_get; done; dmesg -c | grep -o 'inst[0-9]: 0x[0-9a-f]*'" 15
ping -c 3 -i 0.2 192.168.1.1 | grep -o '[0-9]* packets received'
