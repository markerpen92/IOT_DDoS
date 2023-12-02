from MeasureTraffic import ReadRecord
from MeasureTraffic import AnalysisRecord
import traceback
import time


def GetConnectedTime(IOTDevicesInfo) : 
    try : 
        filename = "./MeasureConnectedTime.txt"
        RecordFirstLine = ReadRecord(filename)
        if RecordFirstLine == None : 
            time.sleep(2)
            return
        srcip = AnalysisRecord(RecordFirstLine)
        if srcip == None : 
            print("Read srcip is None")
            exit(1)
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
            print(f"Connected Time from IP[{srcip}] is - {IOTDevicesInfo[srcip]['ConnectedTime']} || time : {IOTDevicesInfo[srcip]['StartTime']} ~ {IOTDevicesInfo[srcip]['EndTime']}\n\n\n\n\n\n")
    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> MeasureConnectedTime : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)