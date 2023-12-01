from ServiceProviding import ServiceProvide
from scapy.all import *
import threading

# Forwarding
LS_IP = "10.0.0.3"
RS_IP = "12.0.0.4"
WhiteList = [RS_IP]

# Write Record in 'Connect time' file  &  'Traffic' file  &  'CPU usage rate' file
ConnectedTimeRecord = "./MeasureConnectedTime.txt"
TrafficRecord = "./MeasureTraffic.txt"
CPUOccupyRecord = "./MeasureCPUOccupy.txt"

def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a') as file :
                file.write(input_string + '\n')
            print(f'String Add into end of file:{filename}!')
    except Exception as e :
        print(f'Error Msg : {e}')


def packetParse(ThePacket) : 
    try : 
        data = ThePacket.get_payload()
        packet = IP(data)
        print("Receive Packet info:")
        print(packet.summary())
        DstIP = packet[IP].dst
        SrcIP = packet[IP].src
        DstPort = packet[IP].dport

        if DstIP in WhiteList : 
            PayloadDate = "0"
            if Raw in packet[Raw] : 
                PayloadDate =  packet[Raw].load.decode('utf-8')
            ReplyRequest = ServiceProvide(PayloadDate)

            inputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[Payload]-{PayloadDate}"
            append_string_to_file(inputstr , ConnectedTimeRecord)
            append_string_to_file(inputstr , TrafficRecord)
            append_string_to_file(inputstr , CPUOccupyRecord)

            print(PayloadDate)
            if ReplyRequest != None : 
                SendLSPkt = IP(src=SrcIP, dst=LS_IP) / TCP(dport=DstPort) / Raw(load=PayloadDate)
                send(SendLSPkt)
            else : 
                ThePacket.accept()

    except Exception as e :
        print("Now In Exp")
        print(f'Error Msg : {e}')