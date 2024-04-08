import re
import time
import traceback

# Main Function : GetTraffic

def ReadRecord(filename) : 
    with open(filename , 'r+') as file : 
        lines = file.readlines()
        if lines : 
            FirstLine = lines.pop(0)
            file.seek(0)
            # print(lines)
            file.writelines(lines)
            file.truncate()
            file.close()
            # print(FirstLine)
            return FirstLine
        else : 
            return

def AnalysisRecord(record) : 
    pattern = r"\[Src IP\]-(?P<SrcIP>[\d\.]+)"

    match = re.search(pattern, record)
    if match:
        src_ip = match.group(1)
        return src_ip
    return None

def GetPktsizeRecord(record) : 
    pattern = r"\[PktSize\]-(?P<PktSize>.*)"
    
    match = re.search(pattern, record)
    if match:
        pktsize = match.group("PktSize")
        return pktsize
    return None

def GetTraffic(IOTDevicesInfo , BlockList) : 
    try : 
        filename = "Measurement/Record/MeasureTraffic.txt"
        RecordFirstLine = ReadRecord(filename)
        if RecordFirstLine == None : 
            time.sleep(2)
            return
        srcip = AnalysisRecord(RecordFirstLine)
        pktsize = GetPktsizeRecord(RecordFirstLine)
        if srcip == None : 
            print("Read srcip is None")
            exit(1)
        if srcip not in IOTDevicesInfo or srcip in BlockList : 
            return

        IOTDevicesInfo[srcip]["PktAmount"] += 1
        IOTDevicesInfo[srcip]["TotalRxBytes"] += int(pktsize)
        if IOTDevicesInfo[srcip]["ConnectedTime"] == 0 : 
            # print(f"<Warning Event> SrcIP[{srcip}] ConnectedTime is 0 -> {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']} || PktAmount : {IOTDevicesInfo[srcip]['PktAmount']} || TrustValue-{IOTDevicesInfo[srcip]['TrustValue']}\n\n\n")
            IOTDevicesInfo[srcip]["Throughput"] = IOTDevicesInfo[srcip]["TotalRxBytes"]*8.0/1000000/1
            return
        IOTDevicesInfo[srcip]["Throughput"] = IOTDevicesInfo[srcip]["TotalRxBytes"]*8.0/1000000/IOTDevicesInfo[srcip]["ConnectedTime"]

    except Exception as e : 
        traceback_str = traceback.format_exc()
        # print(f"<Error> MeasureTraffic : {e}")
        # print(f"Traceback : {traceback_str}")
        time.sleep(2.0)