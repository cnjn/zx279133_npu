#!/bin/sh
# On the ONT: rng.sh probe|restore FIRST LAST  (decimal pcs) -- hot-patch a range of instructions.
S=/sys/devices/platform/np/ppu_debug/inst_set
mode=$1; a=$2; b=$3
awk -v a="$a" -v b="$b" -v m="$mode" 'NR-1>=a && NR-1<=b {
    if (m == "probe") printf "%x 07ffffff ffffffff\n", NR-1; else printf "%x %s %s\n", NR-1, $1, $2 }' /var/tmp/orig.txt |
while read pc h l; do echo "$pc $h $l" > $S; done
dmesg -c > /dev/null
echo "$mode $a-$b done"
