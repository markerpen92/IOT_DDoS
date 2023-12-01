from ServiceProviding import ServiceProvide
from scapy.all import *
import threading

# Forwarding
LS_IP = "10.0.0.3"
RS_IP = "12.0.0.4"
WhiteList = [RS_IP]
ResponseList = []

# Write Record in 'Connect time' file  &  'Traffic' file  &  'CPU usage rate' file
ConnectedTimeRecord = "./MeasureConnectedTime.txt"
TrafficRecord = "./MeasureTraffic.txt"
CPUOccupyRecord = "./MeasureCPUOccupy.txt"

# lock = threading.Lock()
def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a') as file :
                file.write(input_string + '\n')
            print(f'String Add into end of file:{filename}!')
    except Exception as e :
        print(f'Error Msg : {e}')

def CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP) : 
    if SrcIP in IOTDevicesInfo : 
        return
    else : 
        Info = {
            SrcIP : {
                "StartTime" : 0 ,
                "EndTime"   : 0 ,
                "ConnectedTime" : 0 , 
                "TotalRxBytes" : 0 , 
                "Throughput"    : 0
            }
        }
        IOTDevicesInfo.update(Info)

'''
File Record : 
    Connected TIme Record - [srcip , dstip , dstport , service]
    Traffic Record - [srcip , dstip , dstport , pktsize]
    CPU Record - [srcip , dstip , dstport , service]
'''

def packetParse(ThePacket , IOTDevicesInfo) : 
    try : 
        data = ThePacket.get_payload()
        packet = IP(data)
        print("Receive Packet info : " , end="")
        print(packet.summary())
        DstIP = packet[IP].dst
        SrcIP = packet[IP].src
        DstPort = packet[IP].dport
        
        if DstIP in WhiteList : 
            CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP)
            PayloadData = "0"
            if Raw in packet : 
                PayloadData = packet[Raw].load.decode('utf-8')
            ReplyRequest = ServiceProvide(PayloadData)
            print(f"=====  The Payload Data : {PayloadData} =====")
            
            ConnectedTimeInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[ReplyRequest]-{ReplyRequest}"
            TrafficInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[PktSize]-{len(PayloadData)}"
            CPUUseRateInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[ReplyRequest]-{ReplyRequest}"
            
            append_string_to_file(ConnectedTimeInputstr , ConnectedTimeRecord)
            append_string_to_file(TrafficInputstr , TrafficRecord)
            append_string_to_file(CPUUseRateInputstr , CPUOccupyRecord)

            ResponseList.append(SrcIP)

            print(f"The ReplyRequest : {ReplyRequest} !!!!!")
            if ReplyRequest != None : 
                print("~~~Send to LS~~~")
                SendLSPkt = IP(src=SrcIP, dst=LS_IP) / TCP(dport=DstPort) / Raw(load=PayloadData)
                send(SendLSPkt)
            else : 
                print("~~~Send to RS~~~")
                ThePacket.accept()
            return

        elif DstIP in ResponseList : 
            print(f"Resopnse from SRC-{SrcIP} to DST-{DstIP}\n\n")
            ResponseList.remove(DstIP)
            ThePacket.accept()
            return

    except Exception as e : 
        print("Now In Exp")
        print(f'Error Msg : {e}')