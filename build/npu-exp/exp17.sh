cd /tmp; D=/sys/devices/platform/np/ppu_debug
r(){ ./npd mem 0x24000 3; ./npd mem 0x20009 1; ./npd mem 0x24032 1; ./npd mem 0x24040 8; }
./npd 0x800 1 >/dev/null
./npd 0x808 0 >/dev/null
echo d57 > $D/break_point_set
sleep 3
echo "== halted?"; r
./npd mem 0x25140 32 > a.txt; ./npd mem 0x25160 32 >> a.txt; ./npd mem 0x25180 1 >> a.txt
for m in 1 2 3 4 5 6 7; do ./npd mem $((0x25140 + m*256)) 4; done
sleep 1
./npd mem 0x25140 32 > b.txt; ./npd mem 0x25160 32 >> b.txt;./npd mem 0x25180 1 >> b.txt
echo "== spr me0 (a vs b)"; paste a.txt b.txt | awk '{print $1,$2,$4}' | head -66
echo d57 2906a76 3a001 > $D/inst_set
./npd 0x804 0x02906a76 0x0003a001 >/dev/null
./npd 0x801 0xff >/dev/null
sleep 1
echo "== after continue"; r
./npd 0x808 0xff >/dev/null
./npd 0x800 0 >/dev/null
./npd mem 0x24002 1
dmesg -c >/dev/null; echo d57 > $D/inst_get; dmesg -c | grep -o 'inst3: 0x[0-9a-f]*'
echo DONE
