from ServiceProviding import ServiceProvide
from scapy.all import *
import threading
import traceback

# main function : packetParse

# Forwarding
LS_IP = "10.0.0.3"
RS_IP = "12.0.0.4"
WhiteList = [RS_IP]
ResponseList = []

# Write Record in 'Connect time' file  &  'Traffic' file  &  'CPU usage rate' file
ConnectedTimeRecord = "./Measurement/Record/MeasureConnectedTime.txt"
TrafficRecord = "./Measurement/Record/MeasureTraffic.txt"
CPUOccupyRecord = "./Measurement/Record/MeasureCPUOccupy.txt"


def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a+') as file :
                file.write(input_string + '\n')
                file.close()
            # print(f'String Add into end of file:{filename}! || Content : {input_string}')

    except Exception as e :
        print(f'Error Msg : {e}')

def CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP , ProtocalType , SynOrFin) : 
    if SrcIP in IOTDevicesInfo : 
        return
    else : 
        Info = {
            SrcIP : {
                "ProtocalType" : ProtocalType , 
                # "SynOrFin"     : SynOrFin     , 
                "StartTime" : 0 ,
                "EndTime"   : 0 ,
                "ConnectedTime" : 0 , 
                "PktAmount" : 0 ,
                "TotalRxBytes"  : 0 , 
                "Throughput"    : 0 , 
                "IOTInfoIsChanged" : False , 
                "TrustValue"    : 100
            }
        }
        IOTDevicesInfo.update(Info)

'''
File Record : 
    Connected TIme Record - [srcip , protocaltype , SynOrFin , PktTime]
    Traffic Record - [srcip , dstip , dstport , pktsize]
    CPU Record - [srcip , dstip , dstport , service]
'''

def packetParse(ThePacket , IOTDevicesInfo) : 
    try : 
        data = ThePacket.get_payload()
        packet = IP(data)
        # print("Receive Packet info : " , end="")
        # print(packet.summary())
        DstIP = packet[IP].dst
        SrcIP = packet[IP].src
        DstPort = packet[IP].dport
        
        if DstIP in WhiteList : 
            ProtocalType = SynOrFin = "None"
            if TCP in packet : 
                ProtocalType = "TCP"
                if packet[TCP].flags.S : 
                    SynOrFin = "SYN"
                elif packet[TCP].flags.F : 
                    SynOrFin = "FIN"
            elif UDP in packet : 
                ProtocalType = "UDP"
            CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP , ProtocalType , SynOrFin)
            PayloadData = "0"
            if Raw in packet : 
                PayloadData = packet[Raw].load.decode('utf-8' , 'ignore')
            ReplyRequest = ServiceProvide(PayloadData)
            # print(f"=====  The Payload Data : {PayloadData} =====")
            ConnectedTimeInputstr = f"[Src IP]-{SrcIP}\t[ProtocalType]-{ProtocalType}\t[Syn or Fin]-{SynOrFin}\t[PktTime]-{time.ctime()}"
            TrafficInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[PktSize]-{len(PayloadData)}"
            CPUUseRateInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[ReplyRequest]-{ReplyRequest}"
            
            append_string_to_file(ConnectedTimeInputstr , ConnectedTimeRecord)
            append_string_to_file(TrafficInputstr , TrafficRecord)
            append_string_to_file(CPUUseRateInputstr , CPUOccupyRecord)

            ResponseList.append(SrcIP)

            # print(f"The ReplyRequest : {ReplyRequest} !!!!!")
            if ReplyRequest != None : 
                # print("~~~Send to LS~~~")
                SendLSPkt = IP(src=SrcIP, dst=LS_IP) / TCP(dport=DstPort) / Raw(load=PayloadData)
                send(SendLSPkt)
            else : 
                # print("~~~Send to RS~~~")
                ThePacket.accept()
            return

        elif DstIP in ResponseList : 
            # print(f"Resopnse from SRC-{SrcIP} to DST-{DstIP}\n\n")
            ResponseList.remove(DstIP)
            ThePacket.accept()
            return

    except Exception as e : 
        print("Now In Exp")
        traceback_str = traceback.format_exc()
        print(f'Error Msg : {e}')
        print(f"Traceback: {traceback_str}")