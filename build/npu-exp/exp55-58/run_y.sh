cd /tmp/ontser.WZUED8
for v in $(cat e56/list); do
  python3 ser.py "sh /tmp/e56/$v.apply; echo go" 20 >/dev/null
  sudo -n tcpdump -i en8 -p -c 2 -nn -XX -s 400 'icmp and greater 200 and src host 192.168.1.1' > /tmp/mac_td.txt 2>/dev/null &
  sleep 1
  python3 ser.py "ping -c 2 -s 300 192.168.1.2 >/dev/null 2>&1; sh /tmp/e56/$v.restore" 20 >/dev/null
  sleep 1; sudo -n killall tcpdump 2>/dev/null
  echo "=== $v"; cat /tmp/mac_td.txt
done
