cd /tmp; D=/sys/devices/platform/np/ppu_debug
snap(){ ./npd mem 0x20000 0x200; ./npd mem 0x24000 0x200; ./npd mem 0x25000 0x900; }
snap > s0.txt
./npd 0x800 1 >/dev/null
snap > s1.txt
echo d57 > $D/break_point_set
sleep 3
snap > s2.txt
sleep 1
snap > s3.txt
echo d57 2906a76 3a001 > $D/inst_set
./npd 0x804 0x02906a76 0x0003a001 >/dev/null
./npd 0x801 0xff >/dev/null
./npd 0x800 0 >/dev/null
sleep 1
snap > s4.txt
dmesg -c >/dev/null; echo d57 > $D/inst_get; dmesg -c | grep -o 'inst3: 0x[0-9a-f]*'
paste s0.txt s1.txt s2.txt s3.txt s4.txt | awk '{ if ($2!=$4 || $4!=$6 || $6!=$8 || $8!=$10) print $1, $2, $4, $6, $8, $10 }' | head -150
echo DONE
