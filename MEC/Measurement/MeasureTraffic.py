import re
import time
import traceback

# Main Function : GetTraffic

def ReadRecord(filename) : 
    with open(filename , 'r+') as file : 
        # print("INININININININ\n\n\n\n")
        lines = file.readlines()
        if lines : 
            # print(f"++++==== {len(lines)} ====++++")
            FirstLine = lines.pop(0)
            file.seek(0)
            # print(lines)
            file.writelines(lines)
            file.truncate()
            # time.sleep(1.0)
            # print("Delete first line")
            # LLL = file.readlines()
            # print(f"????==== {len(LLL)} ====????")
            file.close()
            # print(FirstLine)
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
    pattern = r"\[PktSize\]-(?P<PktSize>.*)"
    
    match = re.search(pattern, record)
    if match:
        pktsize = match.group("PktSize")
        return pktsize
    return None

def GetTraffic(IOTDevicesInfo) : 
    try : 
        filename = "Measurement/Record/MeasureTraffic.txt"
        RecordFirstLine = ReadRecord(filename)
        # print(RecordFirstLine)
        if RecordFirstLine == None : 
            time.sleep(2)
            return
        srcip = AnalysisRecord(RecordFirstLine)
        pktsize = GetPktsizeRecord(RecordFirstLine)
        if srcip == None : 
            print("Read srcip is None")
            exit(1)
        IOTDevicesInfo[srcip]["IOTInfoIsChanged"] = True
        IOTDevicesInfo[srcip]["PktAmount"] += 1
        IOTDevicesInfo[srcip]["TotalRxBytes"] += int(pktsize)
        if IOTDevicesInfo[srcip]["ConnectedTime"] == 0 : 
            print(f"<Warning Event> SrcIP[{srcip}] ConnectedTime is 0 -> {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']} || PktAmount : {IOTDevicesInfo[srcip]['PktAmount']}\n\n\n")
            # print(f"Pktsize is : {pktsize}")
            IOTDevicesInfo[srcip]["Throughput"] = IOTDevicesInfo[srcip]["TotalRxBytes"]*8.0/1000000/1
            return
        IOTDevicesInfo[srcip]["Throughput"] = IOTDevicesInfo[srcip]["TotalRxBytes"]*8.0/1000000/IOTDevicesInfo[srcip]["ConnectedTime"]
        # print(f"Pkt Amount : {IOTDevicesInfo[srcip]['PktAmount']}")
    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> MeasureTraffic : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)