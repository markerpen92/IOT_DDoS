import re
import time
import traceback

def ReadRecord(filename) : 
    with open(filename , 'r+') as file : 
        lines = file.readlines()
        if lines : 
            FirstLine = lines.pop(0)
            file.seek(0)
            file.truncate()
            # print("Delete first line")
            file.close()
            return FirstLine
        else : 
            # print(f"<No line to read>{file} has no record")
            return

def AnalysisRecord(record) : 
    pattern = r"\[Src IP\]-(?P<SrcIP>[\d\.]+)"

    match = re.search(pattern, record)
    if match:
        src_ip = match.group(1)
        # print("Src IP:", src_ip)
        return src_ip
    return None

def GetPktsizeRecord(record) : 
    pattern = r"\[PktSize\]-([0-9]+)"

    match = re.search(pattern , record)
    # print(record)
    if match : 
        pktsize = match.group(1)
        return pktsize
    return None

def GetTraffic(IOTDevicesInfo) : 
    try : 
        filename = "./MeasureTraffic.txt"
        RecordFirstLine = ReadRecord(filename)
        if RecordFirstLine == None : 
            time.sleep(2)
            return
        srcip = AnalysisRecord(RecordFirstLine)
        pktsize = GetPktsizeRecord(RecordFirstLine)
        if srcip == None : 
            print("Read srcip is None")
            exit(1)
        IOTDevicesInfo[srcip]["PktAmount"] += 1
        IOTDevicesInfo[srcip]["TotalRxBytes"] += int(pktsize)
        if IOTDevicesInfo[srcip]["ConnectedTime"] == 0 : 
            print(f"<Warning Event> SrcIP[{srcip}] ConnectedTime is 0\n\n\n")
            # print(f"Pktsize is : {pktsize}")
            IOTDevicesInfo[srcip]["Throughput"] = float(pktsize)*1.0*8.0/1000000
            return
        IOTDevicesInfo[srcip]["Throughput"] = IOTDevicesInfo[srcip]["TotalRxBytes"]*8.0/1000000/IOTDevicesInfo[srcip]["ConnectedTime"]
    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> MeasureTraffic : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)