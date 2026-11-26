cd /tmp/ontser.WZUED8
for v in $(cat e56/list); do
  python3 ser.py "sh /tmp/e56/$v.apply; rm -f /tmp/td.txt; (tcpdump -i any -c 20 -nn icmp > /tmp/td.txt 2>&1 &); sleep 1; echo go" 20 >/dev/null
  sudo -n tcpdump -i en8 -c 20 -nn -e icmp > /tmp/mac_td.txt 2>/dev/null &
  sleep 1
  r=$(ping -c 3 -i 0.3 -t 3 192.168.1.1 | grep -o '[0-9]* packets received')
  sleep 1; sudo -n killall tcpdump 2>/dev/null
  echo "=== $v | $r"
  echo "--- mac sees:"; grep -c 'echo request' /tmp/mac_td.txt | sed 's/^/requests: /'; grep -c 'echo reply' /tmp/mac_td.txt | sed 's/^/replies: /'; grep 'echo request' /tmp/mac_td.txt | head -6
  echo "--- board sees:"
  python3 ser.py "sh /tmp/e56/$v.restore; killall tcpdump 2>/dev/null; sleep 1; grep -E 'In|Out|B |M ' /tmp/td.txt | cut -c1-110" 20 | grep -v exit
  ping -c 2 -i 0.3 192.168.1.1 >/dev/null 2>&1
done
