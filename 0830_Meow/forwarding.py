from ServiceProviding import ServiceProvide
from scapy.all import *
from collections import deque
import threading
import traceback

# main function : packetParse

# Forwarding
#LS_IP = None
#RS_IP = ["140.1.1.2","140.1.2.2"]
WhiteList = ["140.1.1.2","140.1.2.2","192.168.10.1","192.168.20.2","192.168.30.1","192.168.40.2"]
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

    except Exception as e :
        print(f'Error Msg : {e}')

def CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP , ProtocalType , SynOrFin) : 
    if SrcIP in IOTDevicesInfo : 
        return
    else : 
        Info = {
            SrcIP : {
                "ProtocalType" : ProtocalType , 
                "StartTime" : 0 ,
                "EndTime"   : 0 ,
                "ConnectedTime" : 0 , 
                "PktAmount" : 0 ,
                "PktAmountHistory" : deque([0]*5+["time"] , maxlen=6) , 
                "TotalRxBytes"  : 0 , 
                "Throughput"    : 0 , 
                "IOTInfoIsChanged" : False , 
                "TrustValue"    : 100 , 
                "connection_count" : {}
            }
        }
        IOTDevicesInfo.update(Info)

'''
File Record : 
    Connected TIme Record - [srcip , protocaltype , SynOrFin , PktTime]
    Traffic Record - [srcip , dstip , dstport , pktsize]
    CPU Record - [srcip , dstip , dstport , service]
'''

def GetConnectedCount(srcip , dstip , IOTDevicesInfo , SynOrFin) : 
    if SynOrFin == "None" : 
        return
    if dstip not in IOTDevicesInfo[srcip]["connection_count"] : 
        ConnectedCountInfo = {
            dstip : 0
        }
        IOTDevicesInfo[srcip]["connection_count"].update(ConnectedCountInfo)
    else : 
        # print("INININININ\n\n\n")
        if SynOrFin == "SYN" : 
            IOTDevicesInfo[srcip]["connection_count"][dstip] += 1
        if SynOrFin == "FIN" : 
            IOTDevicesInfo[srcip]["connection_count"][dstip] -= 1

    # print(f"Connection count from {srcip} to {dstip} : {IOTDevicesInfo[srcip]['connection_count'][dstip]}\n\n\n")


def packetParse(ThePacket , IOTDevicesInfo , BlockList) : 
    try : 
        data = ThePacket.get_payload()
        packet = IP(data)
        # print("Receive Packet info : " , end="")
        # print(packet.summary())
        # print(pkt.show())
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
            print(f'packet windows size: {packet[TCP].window}')
            CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP , ProtocalType , SynOrFin)

            GetConnectedCount(SrcIP , DstIP , IOTDevicesInfo , SynOrFin)
            PayloadData = "0"
            if Raw in packet : 
                PayloadData = packet[Raw].load.decode('utf-8' , 'ignore')
                print(PayloadData)
            ReplyRequest = ServiceProvide(PayloadData)
            ConnectedTimeInputstr = f"[Src IP]-{SrcIP}\t[ProtocalType]-{ProtocalType}\t[Syn or Fin]-{SynOrFin}\t[PktTime]-{time.ctime()}"
            TrafficInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[PktSize]-{len(PayloadData)}"
            CPUUseRateInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[ReplyRequest]-{ReplyRequest}"
            
            append_string_to_file(ConnectedTimeInputstr , ConnectedTimeRecord)
            append_string_to_file(TrafficInputstr , TrafficRecord)
            append_string_to_file(CPUUseRateInputstr , CPUOccupyRecord)

            ResponseList.append(SrcIP)

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