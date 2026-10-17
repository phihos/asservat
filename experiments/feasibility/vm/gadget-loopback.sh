#!/bin/bash
set -euo pipefail
/opt/ig/ig run ghcr.io/inspektor-gadget/gadget/tcpdump:v0.57.0 --disallow-pulling --host --iface lo --runtimes='' --pf 'udp dst port 58888' --snaplen 65535 --output pcap-ng --timeout 6 > /root/gadget.pcapng 2> /root/gadget-capture.log &
collector=$!
sleep 2
python3 - <<'PY'
import socket,struct,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
# A bound receiver prevents ICMP noise; only reserved synthetic payloads are sent.
r=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);r.bind(('127.0.0.1',58888));r.setblocking(False)
for i in range(200):
 s.sendto(b'ASSERVAT-SYNTHETIC-'+struct.pack('!I',i),('127.0.0.1',58888))
 try:r.recv(65535)
 except BlockingIOError:pass
 time.sleep(.005)
PY
wait "$collector"
tshark -r /root/gadget.pcapng -T fields -e ip.src -e udp.dstport -e udp.payload > /root/gadget-rows.tsv
python3 - <<'PY'
from pathlib import Path
rows=Path('/root/gadget-rows.tsv').read_text().splitlines()
assert rows, 'Gadget captured no synthetic packets'
assert all('\t58888\t' in r for r in rows)
print('native PCAPNG opened with tshark; rows:',len(rows))
PY
/opt/ig/ig image list
