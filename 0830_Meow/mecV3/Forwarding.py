from ServiceProviding import ServiceProvide
from scapy.all import *
from collections import deque
import threading
import traceback

# main function : packetParse

# Forwarding
#LS_IP = "10.0.0.3"
RS_IP = ["140.1.1.2","140.1.2.2"]
WhiteList = ["140.1.1.2","140.1.2.2","192.168.10.1","192.168.20.2","192.168.30.1","192.168.40.2"]
ResponseList = []

# Write Record in 'Connect time' file  &  'Traffic' file  &  'CPU usage rate' file
ConnectedTimeRecord = "./Measurement/Record/MeasureConnectedTime.txt"
TrafficRecord = "./Measurement/Record/MeasureTraffic.txt"
CPUOccupyRecord = "./Measurement/Record/MeasureCPUOccupy.txt"
PacketFeatureRecord = "./IPS/record.txt"


def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a+') as file :
                #filter Bad characters
                input_string = input_string.replace('\r', '')   # Data processing(HTML)
                input_string = input_string.replace('\n', '')   # Data processing(HTML) 
                input_string = input_string.replace('\r\n', '') # Data processing(HTML)
                input_string = input_string.replace('\n\r', '') # Data processing(HTML) 
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

            # print(f'==Show packet features==')
            # print(f'packet windows size: {packet[TCP].window}')
            # if Raw in packet : 
            #     print(f'packet paylaod data: {packet[Raw].load.decode("utf-8")}')
            # else : 
            #     print(f'None payload data')
            # print("-------------------------------------------------------------------------------------")

            CreateIOTDevicesInfo(IOTDevicesInfo , SrcIP , ProtocalType , SynOrFin)
            GetConnectedCount(SrcIP , DstIP , IOTDevicesInfo , SynOrFin)

            PayloadData = "0"
            if Raw in packet : 
                PayloadData = packet[Raw].load.decode('utf-8' , 'ignore')
            ReplyRequest = ServiceProvide(PayloadData)
            ConnectedTimeInputstr = f"[Src IP]-{SrcIP}\t[ProtocalType]-{ProtocalType}\t[Syn or Fin]-{SynOrFin}\t[PktTime]-{time.ctime()}"
            TrafficInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[PktSize]-{len(PayloadData)}"
            CPUUseRateInputstr = f"[Src IP]-{SrcIP}\t[Dst IP]-{DstIP}\t[Dstport]-{DstPort}\t[ReplyRequest]-{ReplyRequest}"



            PacketFeatureInptstr = f"{SrcIP} {DstIP} {packet[TCP].window} {PayloadData}"
            patterns = {
                1 : r'Connection: keep-alive' , 
                2 : r'Connection: keep-alive(?![\r\n])' , 
                3 : r'Connection: keep-alive\r\n(?![\r\n])' , 
                4 : r'Content-Length: (\d+)\r\n'
            }

            Patterns_of_Payload = ''
            condiction_count = 0


            for condiction , pattern in patterns.items : 
                matches = re.findall(pattern , PayloadData)

                if condiction==1 and matches : 
                    Patterns_of_Payload += '1 '
                    condiction_count += 1

                elif (condiction==2 or condiction==3) and matches : 
                    Patterns_of_Payload += '1 '
                    condiction_count += 1

                elif condiction==3 and matches : 
                    Patterns_of_Payload += f'{matches}'
                    condiction_count += 1


            if condiction_count >= 2 : 
                PayloadData = Patterns_of_Payload
                PacketFeatureInptstr = f"{packet[TCP].window} {PayloadData}"
                # print(PayloadData , end='\n\n\n\n')
                if SrcIP not in RS_IP :append_string_to_file(PacketFeatureInptstr, PacketFeatureRecord)
           
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