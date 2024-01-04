from scapy.all import *

src_ip = "127.0.0.1"

# Target machine
dstIP = "127.0.0.1"
dstPort = 80

# Packet Archi
ipHeader = IP(src=src_ip, dst=dstIP)
tcpHeader = TCP(sport=RandShort(), dport=dstPort)
httpGetRequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

packet = ipHeader / tcpHeader / Raw(load=httpGetRequest)

# 使用sniff函数来监听响应，设置超时时间
response = sniff(filter="tcp", timeout=5)

if response:
    print("Response")
    print(response[0].show())
else:
    print("No message received!!")