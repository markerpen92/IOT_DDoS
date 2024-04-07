import socket
import netfilterqueue
import os
from scapy.all import IP, Raw, UDP, send
import hashlib
import threading

LS_IP = "10.0.0.3"
RS_IP = "11.0.0.3"

def forward():
    print("forward!")
    os.system("ip address add 192.168.1.254/24 brd + dev mec-eth0")
    os.system("ip address add 11.0.0.254/24    brd + dev mec-eth1")
    os.system("ip address add 10.0.0.254/24    brd + dev mec-eth2")
    os.system("ip route add 12.0.0.0/24 via 11.0.0.253           ")

def exit():
    # 這邊還要修改 刪除設定有bug
    while 1:
        if input() == "y":
            os.system("ip address del 192.168.1.254/24 dev mec-eth0")
            os.system("ip address del 11.0.0.254/24 dev mec-eth1")
            os.system("ip address del 10.0.0.254/24 dev mec-eth2")
            os.system("ip route del 12.0.0.0/24 via 11.0.0.253")
            print("settings were cleared!")
            break
            import sys
            sys.exit()
        else: print("Do you want to exit?(y/n)")



def packetParse(payload):
    data = payload.get_payload()
    pkt = IP(data)

    

    if IP in pkt:
        DST_IP = pkt[IP].dst
        SRC_IP = pkt[IP].src

        print("Destination IP:", DST_IP)
        
        # print packet payload
        payload_data=""
        if Raw in pkt:
            payload_data = pkt[Raw].load.decode('utf-8')
            print("Payload Data:", payload_data)

        # hash packet payload
        hash_data = payload_data
        hash_value = hashlib.sha256(hash_data.encode()).hexdigest()

        #(The data should be retrieved from the local server.)
        check1 = hashlib.sha256("hello".encode()).hexdigest()
        
        # print("Hash Value:", hash_value)
        if hash_value == check1:

            # 這裡應該要Send to LS 
            print("There is data on the local server.")
            ip_packet = IP(src=SRC_IP, dst=LS_IP) / UDP() / Raw(load=payload_data)
            send(ip_packet)
        else:

            print("There is no data on the local server.")
            ip_packet = IP(src=SRC_IP, dst=RS_IP) / UDP() / Raw(load=payload_data)
            send(ip_packet)
        
        print("=" * 40)
    
    payload.accept()

def main():
    os.system('iptables -A INPUT -j NFQUEUE --queue-num 0')

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, packetParse)

    try:
        queue.run()  # Main loop
    except KeyboardInterrupt:
        queue.unbind()  # server to server concat
        # Rule delete
        os.system('iptables -D INPUT -j NFQUEUE --queue-num 0')

if __name__ == "__main__":
    forward()
    threading.Thread(target=main).start()
    threading.Thread(target=exit).start()

