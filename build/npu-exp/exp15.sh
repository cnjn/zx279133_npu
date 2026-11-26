cd /tmp; D=/sys/devices/platform/np/ppu_debug
echo "vld0 $(./npd 0x811)"
echo "en $(./npd 0x800 1)"
echo d57 > $D/break_point_set
sleep 3
echo "vld1 $(./npd 0x811)"
for m in 0 1 2 3 4 5 6 7; do echo "bp$m $(NPDBG_N=3 ./npd 0x805 $m)"; done
for m in 0 1; do echo "spr$m $(NPDBG_N=34 ./npd 0x80d $m)"; echo "rsp$m $(NPDBG_N=34 ./npd 0x80f $m)"; echo "flg$m $(NPDBG_N=4 ./npd 0x810 $m)"; done
echo d57 2906a76 3a001 > $D/inst_set
echo "real $(./npd 0x804 0x02906a76 0x0003a001)"
echo "cont $(./npd 0x801 0xff)"
echo "dis $(./npd 0x800 0)"
sleep 1
echo "vld2 $(./npd 0x811)"
dmesg -c >/dev/null; echo d57 > $D/inst_get; dmesg -c | grep -o 'inst3: 0x[0-9a-f]*'
echo DONE
