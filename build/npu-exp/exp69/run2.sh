cd /tmp/ontser.WZUED8
python3 ser.py "sh /tmp/e69/refl.apply; echo applied" 30 | grep applied
sudo -n tcpdump -i en8 -c 2 -nn -v 'udp and src host 192.168.1.1' > /tmp/mac_td.txt 2>/dev/null &
sleep 1; python3 e69/udp_test.py | tail -1; sleep 1; sudo -n killall tcpdump 2>/dev/null
grep -o 'ttl [0-9]*\|bad cksum[^)]*\|udp sum ok\|bad udp cksum[^,]*' /tmp/mac_td.txt | sort | uniq -c
python3 ser.py "cat /proc/stat | head -1" 10 | head -1 > /tmp/cpu0.txt
python3 e69/flood.py
python3 ser.py "cat /proc/stat | head -1" 10 | head -1 > /tmp/cpu1.txt
python3 -c "
a=list(map(int,open('/tmp/cpu0.txt').read().split()[1:])); b=list(map(int,open('/tmp/cpu1.txt').read().split()[1:]))
d=[y-x for x,y in zip(a,b)]; print('board cpu busy during flood: %.1f%%' % (100*(1-(d[3]+d[4])/sum(d))))"
python3 ser.py "sh /tmp/e69/refl.restore >/dev/null; echo restored" 30 | grep restored
