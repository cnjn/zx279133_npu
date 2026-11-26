cd /tmp/ontser.WZUED8
for v in $(cat e56/list); do
  python3 ser.py "sh /tmp/e56/$v.apply; rm -f /tmp/td.txt; (tcpdump -i any -c 16 -nn -XX -s 400 'greater 200' > /tmp/td.txt 2>&1 &); sleep 1; echo go" 20 >/dev/null
  ping -c 1 -s 300 -t 2 192.168.1.1 >/dev/null 2>&1
  sudo -n python3 e56/sendraw.py en8 > /dev/null
  sleep 1
  echo "=== $v"
  python3 ser.py "sh /tmp/e56/$v.restore; killall tcpdump 2>/dev/null; sleep 1; cat /tmp/td.txt | grep -vE 'listening|verbose|data link'" 20 | grep -v exit
  ping -c 1 192.168.1.1 >/dev/null 2>&1
done
