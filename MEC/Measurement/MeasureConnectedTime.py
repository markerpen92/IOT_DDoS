from .MeasureTraffic import ReadRecord
from .MeasureTraffic import AnalysisRecord
import sys
sys.path.append("Measurement/Record")
import traceback
import time
import re

def GetSYNorFINflags(record) : 
    pattern = r"\[Syn or Fin\]-(?P<SynOrFin>[^\t]+)"

    match = re.search(pattern, record)
    if match:
        SYNorFIN = match.group("SynOrFin")
        return SYNorFIN
    return None

def GetPktTime(record) : 
    pattern = r"\[PktTime\]-(?P<PktTime>.*)"

    match = re.search(pattern, record)
    if match:
        pkttime = match.group(1)
        return pkttime
    return None


def GetConnectedTime(IOTDevicesInfo , BlockList) : 
    try : 
        filename = "Measurement/Record/MeasureConnectedTime.txt"
        RecordFirstLine = ReadRecord(filename)
        # print(RecordFirstLine)
        if RecordFirstLine == None : 
            time.sleep(2)
            return
        srcip = AnalysisRecord(RecordFirstLine)
        SYNorFIN = GetSYNorFINflags(RecordFirstLine)
        PktTime = GetPktTime(RecordFirstLine)
        if srcip == None : 
            print("Read srcip is None")
            time.sleep(2.0)
            return
        if SYNorFIN == None : 
            print("Read SYNorFIN is None")
            time.sleep(2.0)
            return
        if PktTime == None : 
            print("Read PktTime is None")
            time.sleep(2.0)
            return
        if srcip not in IOTDevicesInfo or srcip in BlockList : 
            return
        IOTDevicesInfo[srcip]["IOTInfoIsChanged"] = True

        if IOTDevicesInfo[srcip]["ProtocalType"] == "TCP" and SYNorFIN == "SYN" : # or (IOTDevicesInfo[srcip]['StartTime'] == 0 and IOTDevicesInfo[srcip]["ProtocalType"] == "TCP") : 
            IOTDevicesInfo[srcip]['EndTime'] = 0
            IOTDevicesInfo[srcip]['ConnectedTime'] = 0
            IOTDevicesInfo[srcip]['StartTime'] = GetPktTime(RecordFirstLine)

            #create pkt amount history to measuere distribution in each sec
            if IOTDevicesInfo[srcip]['PktAmountHistory'] : 
                IOTDevicesInfo[srcip]['PktAmountHistory'].pop()
            IOTDevicesInfo[srcip]['PktAmountHistory'].extend([0, PktTime])
        elif IOTDevicesInfo[srcip]['StartTime'] != 0 and IOTDevicesInfo[srcip]["ProtocalType"] == "TCP" : 
            IOTDevicesInfo[srcip]['EndTime'] = GetPktTime(RecordFirstLine)
            startTime = time.strptime(IOTDevicesInfo[srcip]["StartTime"], "%a %b %d %H:%M:%S %Y")
            endTime   = time.strptime(IOTDevicesInfo[srcip]["EndTime"], "%a %b %d %H:%M:%S %Y")
            connectedTime = time.mktime(endTime)-time.mktime(startTime)
            IOTDevicesInfo[srcip]['ConnectedTime'] = connectedTime
            print(f"Connected Time from IP[{srcip}] is - {IOTDevicesInfo[srcip]['ConnectedTime']} || time : {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']} || PktAmount--{IOTDevicesInfo[srcip]['PktAmount']} || TrustValue-{IOTDevicesInfo[srcip]['TrustValue']}\n\n\n\n\n\n")
        
        # For UDP Connected Time (not real connected time , this function is easy to know thr)
        elif IOTDevicesInfo[srcip]['StartTime'] == 0 and IOTDevicesInfo[srcip]["ProtocalType"] == "UDP" : 
            if IOTDevicesInfo[srcip]['EndTime'] != 0 : 
                print("Error Endtime")
                exit(1)
            IOTDevicesInfo[srcip]['StartTime'] = time.ctime()
        elif IOTDevicesInfo[srcip]['StartTime'] != 0 and IOTDevicesInfo[srcip]["ProtocalType"] == "UDP" : 
            IOTDevicesInfo[srcip]['EndTime'] = time.ctime()
            startTime = time.strptime(IOTDevicesInfo[srcip]["StartTime"], "%a %b %d %H:%M:%S %Y")
            endTime   = time.strptime(IOTDevicesInfo[srcip]["EndTime"], "%a %b %d %H:%M:%S %Y")
            connectedTime = time.mktime(endTime)-time.mktime(startTime)
            IOTDevicesInfo[srcip]['ConnectedTime'] = connectedTime
            print(f"Connected Time from IP[{srcip}] is - {IOTDevicesInfo[srcip]['ConnectedTime']} || time : {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']} || PktAmount--{IOTDevicesInfo[srcip]['PktAmount']} || TrustValue-{IOTDevicesInfo[srcip]['TrustValue']}\n\n\n\n\n\n")

        # these condition is to check distribution of pktamount in each sec
        if time.mktime(time.strptime(PktTime))-time.mktime(time.strptime(IOTDevicesInfo[srcip]['PktAmountHistory'][-1])) < 1 : 
            IOTDevicesInfo[srcip]['PktAmountHistory'][-2] += 1
        else : 
            IOTDevicesInfo[srcip]['PktAmountHistory'].pop()
            IOTDevicesInfo[srcip]['PktAmountHistory'].extend([0,PktTime])

    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> MeasureConnectedTime : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)


'''
!!! Data Structure of IOTDevicesInfo[srcip]['PktAmountHistory'] !!!

O   O   O   O    maxlen=4
P1  ST1
if now-ST1<1 : array[-2]++
if now-ST1>1 : pop array[-1] && append [0.0] && append ST2 
P1  P2  ST2
if now-array[-1](ST2)<1 : array[-2]++
else : pop array[-1] && append [0.0] && append ST3
P1  P2  P3  ST3

'''