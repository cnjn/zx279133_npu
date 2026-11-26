cd /tmp/ontser.WZUED8
for v in $(cat e56/list); do
  python3 ser.py "sh /tmp/e56/$v.apply; rm -f /tmp/td.txt; (tcpdump -i any -c 4 -nn -XX -s 400 'icmp and greater 200' > /tmp/td.txt 2>&1 &); sleep 1; echo go" 20 >/dev/null
  sudo -n tcpdump -i en8 -p -c 4 -nn -XX -s 400 'icmp and greater 200' > /tmp/mac_td.txt 2>/dev/null &
  sleep 1
  ping -c 2 -i 0.4 -s 300 -t 3 192.168.1.1 >/dev/null 2>&1
  sleep 1; sudo -n killall tcpdump 2>/dev/null
  echo "=== $v"
  echo "--- MAC"; cat /tmp/mac_td.txt
  echo "--- BOARD"
  python3 ser.py "sh /tmp/e56/$v.restore; killall tcpdump 2>/dev/null; sleep 1; cat /tmp/td.txt" 20 | grep -v exit
  ping -c 2 -i 0.3 192.168.1.1 >/dev/null 2>&1
done
