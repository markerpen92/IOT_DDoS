from .MeasureTraffic import ReadRecord
from .MeasureTraffic import AnalysisRecord
import sys
sys.path.append("Measurement/Record")
import traceback
import time

def GetConnectedTime(IOTDevicesInfo) : 
    try : 
        filename = "Measurement/Record/MeasureConnectedTime.txt"
        RecordFirstLine = ReadRecord(filename)
        if RecordFirstLine == None : 
            time.sleep(2)
            return
        srcip = AnalysisRecord(RecordFirstLine)
        if srcip == None : 
            print("Read srcip is None")
            exit(1)
        # For TCP Connected Time
        if IOTDevicesInfo[srcip]['StartTime'] == 0 and IOTDevicesInfo[srcip]["ProtocalType"] == "TCP" and IOTDevicesInfo[srcip]["SynOrFin"] == "SYN" : 
            if IOTDevicesInfo[srcip]['EndTime'] != 0 : 
                print("Error Endtime")
                exit(1)
            IOTDevicesInfo[srcip]['EndTime'] = 0
            IOTDevicesInfo[srcip]['ConnectedTime'] = 0
            IOTDevicesInfo[srcip]['StartTime'] = time.ctime()
        elif IOTDevicesInfo[srcip]['StartTime'] != 0 and IOTDevicesInfo[srcip]["ProtocalType"] == "TCP" : 
            IOTDevicesInfo[srcip]['EndTime'] = time.ctime()
            startTime = time.strptime(IOTDevicesInfo[srcip]["StartTime"], "%a %b %d %H:%M:%S %Y")
            endTime   = time.strptime(IOTDevicesInfo[srcip]["EndTime"], "%a %b %d %H:%M:%S %Y")
            connectedTime = time.mktime(endTime)-time.mktime(startTime)
            IOTDevicesInfo[srcip]['ConnectedTime'] = connectedTime
            if IOTDevicesInfo[srcip]["SynOrFin"] == "FIN" : 
                IOTDevicesInfo[srcip]['StartTime'] = 0
                IOTDevicesInfo[srcip]['EndTime'] = 0
                IOTDevicesInfo[srcip]['ConnectedTime'] = 0
            print(f"Connected Time from IP[{srcip}] is - {IOTDevicesInfo[srcip]['ConnectedTime']} || time : {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']} || PktAmount--{IOTDevicesInfo[srcip]['PktAmount']}\n\n\n\n\n\n")
        
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
            print(f"Connected Time from IP[{srcip}] is - {IOTDevicesInfo[srcip]['ConnectedTime']} || time : {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']} || PktAmount--{IOTDevicesInfo[srcip]['PktAmount']}\n\n\n\n\n\n")

    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> MeasureConnectedTime : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)