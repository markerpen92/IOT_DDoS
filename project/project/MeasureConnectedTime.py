from MeasureTraffic import ReadRecord
from MeasureTraffic import AnalysisRecord
import time

def GetConnectedTime(IOTDevicesInfo) : 
    filename = "./MeasureConnectedTime.txt"
    RecordFirstLine = ReadRecord(filename)
    srcip = AnalysisRecord(RecordFirstLine)
    if srcip == None : 
        print("Read srcip is None")
        exit(1)
    print(IOTDevicesInfo)
    if IOTDevicesInfo[srcip]['StartTime'] == 0 : 
        if IOTDevicesInfo[srcip]['EndTime'] != 0 : 
            print("Error Endtime")
            exit(1)
        IOTDevicesInfo[srcip]['StartTime'] = time.ctime()
    else : 
        IOTDevicesInfo[srcip]['EndTime'] = time.ctime()

        startTime = time.strptime(IOTDevicesInfo[srcip]["StartTime"], "%a %b %d %H:%M:%S %Y")
        endTime   = time.strptime(IOTDevicesInfo[srcip]["EndTime"], "%a %b %d %H:%M:%S %Y")
        connectedTime = time.mktime(endTime)-time.mktime(startTime)
        IOTDevicesInfo[srcip]['ConnectedTime'] = connectedTime