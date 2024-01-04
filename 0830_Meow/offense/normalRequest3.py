from scapy.all import *


load_layer("http")

Request = HTTP() / HTTPRequest(
    Connection=b'keep-alive',
    Host=b'127.0.0.1'
)

with TCP_client.tcplink(HTTP, "127.0.0.1", 80) as tcp_connection:
    #send Reqeust 
    http_response = tcp_connection.sr1(Request)


if http_response:
    tcp_connection.close()

else:
    print("No response received.")