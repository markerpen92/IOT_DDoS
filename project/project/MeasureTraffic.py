import re

def ReadRecord(filename) : 
    with open(filename , 'r+') as file : 
        lines = file.readlines()
        if lines : 
            FirstLine = lines.pop(0)
            file.seek(0)
            file.truncate()
            print("Delete first line")
            file.close()
            return FirstLine
        else : 
            print(f"<No line to read>{file} has no record")

def AnalysisRecord(record) : 
    pattern = r"\[Src IP\]-(?P<SrcIP>[\d\.]+)"

    match = re.search(pattern, record)
    if match:
        src_ip = match.group("SrcIP")
        print("Src IP:", src_ip)
        return src_ip
    return None

def GetPktsizeRecord(record) : 
    pattern = r"\[PktSize\]-([0-9]+)"

    match = re.search(pattern , record)
    if match : 
        pktsize = match.group("PktSize")
        return pktsize
    return None

def GetTraffic(IOTDevicesInfo) : 
    filename = "./MeasureTraffic.txt"
    RecordFirstLine = ReadRecord(filename)
    srcip = AnalysisRecord(RecordFirstLine)
    pktsize = GetPktsizeRecord(RecordFirstLine)
    if srcip == None : 
        print("Read srcip is None")
        exit(1)
    IOTDevicesInfo[srcip]["TotalRxBytes"] += pktsize
    if IOTDevicesInfo[srcip]["ConnectedTime"] == 0 : 
        print(f"<Warning Event> SrcIP[{srcip}] ConnectedTime is 0")
        IOTDevicesInfo[srcip]["Throughput"] = pktsize*1*8.0/1000000
        return
    IOTDevicesInfo[srcip]["Throughput"] = IOTDevicesInfo[srcip]["TotalRxBytes"]*8.0/1000000/IOTDevicesInfo[srcip]["ConnectedTime"]
    