# Mac side: for each variant: push+apply, capture, ping, restore
cd /tmp/ontser.WZUED8
for v in $(cat e56/list); do
  python3 ser.py "sh /tmp/e56/$v.apply; rm -f /tmp/td.txt; (tcpdump -i any -c 2 -nn -XX -s 400 'icmp and src 192.168.1.2' > /tmp/td.txt 2>&1 &); sleep 1; echo go" 20 >/dev/null
  r=$(ping -c 2 -i 0.4 -s 300 -t 3 192.168.1.1 | grep -o '[0-9]* packets received')
  sleep 1
  echo "=== $v | $r"
  python3 ser.py "sh /tmp/e56/$v.restore; killall tcpdump 2>/dev/null; cat /tmp/td.txt | grep -E '^\s+0x'" 20 | grep -v exit
  ping -c 1 192.168.1.1 >/dev/null 2>&1
done
