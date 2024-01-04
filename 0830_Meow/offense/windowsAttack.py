# from scapy.all import IP, TCP, send

# target_ip = "127.0.0.1"
# target_port = 80

# http_get_request = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
# tcp_packet = IP(dst=target_ip) / TCP(dport=target_port, window=1) / http_get_request


# # 发送数据包

# for i in range(200):
#     print("send sucessful")
#     send(tcp_packet)

