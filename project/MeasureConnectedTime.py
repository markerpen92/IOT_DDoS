from MeasureTraffic import ReadRecord
from MeasureTraffic import AnalysisRecord
import time

def GetConnectedTime(IOTDevicesInfo) : 
    filename = "./MeasureConnectedTime.txt"
    RecordFirstLine = ReadRecord(filename)
    srcip = AnalysisRecord(RecordFirstLine)
    if srcip == None : 
        print("Read srcip is Nono")
        exit(1)
    if IOTDevicesInfo[srcip]['StartTime'] == 0 : 
        if IOTDevicesInfo[srcip]['EndTime'] != 0 : 
            print("Error Endtime")
            exit(1)
        IOTDevicesInfo[srcip]['StartTime'] = time.ctime()
    else : 
        IOTDevicesInfo[srcip]['EndTime'] = time.ctime()

    IOTDevicesInfo[srcip]['ConnectedTime'] = time.strptime(IOTDevicesInfo["StartTime"], "%a %b %d %H:%M:%S %Y") - time.strptime(IOTDevicesInfo["EndTime"], "%a %b %d %H:%M:%S %Y")
