printf '\001\007\101\015\274\000\233\117' | dd of=/etc/mcode/mcode_133.bin bs=1 seek=8536 conv=notrunc 2>/dev/null
printf '\001\007\101\015\274\000\205\057' | dd of=/etc/mcode/mcode_133.bin bs=1 seek=9376 conv=notrunc 2>/dev/null
printf '\003\000\000\004\066\361\177\311' | dd of=/etc/mcode/mcode_133.bin bs=1 seek=10640 conv=notrunc 2>/dev/null
printf '\001\007\101\015\274\000\205\057' | dd of=/etc/mcode/mcode_133.bin bs=1 seek=12520 conv=notrunc 2>/dev/null
printf '\003\000\000\004\066\361\177\311' | dd of=/etc/mcode/mcode_133.bin bs=1 seek=13824 conv=notrunc 2>/dev/null
printf '\003\000\000\004\066\361\177\311' | dd of=/etc/mcode/mcode_133.bin bs=1 seek=16168 conv=notrunc 2>/dev/null
echo '95b591278c0c4685b7e136e9e0261aac9528b42e96060f3149f4fca9df975793  /etc/mcode/mcode_133.bin' | sha256sum -c -
