from scapy.all import *

src_ip = "127.0.0.1"

#Target machine
dstIP = "127.0.0.1"
dstPort = 80 


#Packet Archi
ipHeader = IP(src=src_ip, dst=dstIP)
tcpHeader = TCP(sport=RandShort(), dport=dstPort)
httpGetRequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

packet = ipHeader/tcpHeader/Raw(load=httpGetRequest)

response = sr1(packet)

if response:
    print("Response")
    #print(response.summary())
    print(response.show())
else:
    print("No message Receive!!")