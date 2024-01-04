from scapy.all import *

get='GET / HTTP/1.0\n\n'

ip=IP(src="127.0.0.1",dst="127.0.0.1")

port=RandNum(1024,65535)

SYN=ip/TCP(sport=port, dport=80, flags="S", seq=42)

SYNACK=sr1(SYN)

ACK=ip/TCP(sport=SYNACK.dport,dport=80,flags="A",seq=SYNACK.ack,ack=SYNACK.seq+1)/get

reply,error=sr(ACK)

print(reply.show())