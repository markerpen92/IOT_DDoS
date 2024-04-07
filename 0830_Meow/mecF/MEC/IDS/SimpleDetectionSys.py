import threading
import sys
import math
import time
import traceback
from collections import deque
from datetime import datetime
sys.path.append("../IPS")

def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a+') as file :
                file.write(input_string + '\n')
                file.close()
    except Exception as e :
        print(f'Error Msg : {e}')





def SimpleDetectionSystem(IOTDevicesInfo , BlockList , NetworkTimeInfo) : 
    SuspiciousFile = "IPS/SuspiciousList.txt"
    DefenseRecord = "IPS/DefenseRecord.txt"
    Now = datetime.now()
    TimeInterval = (Now - NetworkTimeInfo['NetworkTimeArray'][-1]).total_seconds()


    # print("~"*20)
    if IOTDevicesInfo == {} or TimeInterval<1.0 : 
        return


    try : 
        for srcip in IOTDevicesInfo : 
            # if IOTDevicesInfo[srcip]["IOTInfoIsChanged"] == False or srcip in BlockList : 
            if srcip in BlockList : 
                continue
            ConnectedTime = IOTDevicesInfo[srcip]["ConnectedTime"]
            PktAmount = IOTDevicesInfo[srcip]["PktAmount"]


            if ConnectedTime%100 < 0.001 and ConnectedTime/100 > 1 :  
                IOTDevicesInfo[srcip]["TrustValue"] -= 10
                input_string = f'IP:{srcip} - ConnectTime:{ConnectedTime} - DecreaseTrust:{10} - NowTrust:{IOTDevicesInfo[srcip]["TrustValue"]}'
                append_string_to_file(input_string , DefenseRecord)


            if ConnectedTime > 0 : 
                SuspiciousLevel = (PktAmount/(ConnectedTime+0.003))/200
                LevelArg = 5
                IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*LevelArg
                input_string = f'IP:{srcip} - ConnectTime:{ConnectedTime} - DecreaseTrust(SuspiciousLevel*{LevelArg}):{SuspiciousLevel*5}|(Pkt:{PktAmount}) - NowTrust:{IOTDevicesInfo[srcip]["TrustValue"]}'
                append_string_to_file(input_string , DefenseRecord)
            # elif ConnectedTime == 0 : 
            #     SuspiciousLevel = (PktAmount)/200
            #     IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15


            # To make sure is script attack or not ??
            PktAmountHistory = list(IOTDevicesInfo[srcip]['PktAmountHistory'])[:-1]
            AverageAmountEachSec = sum(PktAmountHistory) / len(PktAmountHistory)
            Dispersion = math.exp(-1*sum(abs(AverageAmountEachSec-amount) for amount in PktAmountHistory))


            if Dispersion > 0.5 and IOTDevicesInfo[srcip]["IOTInfoIsChanged"] : 
                IOTDevicesInfo[srcip]["TrustValue"] -= Dispersion*10
                input_string = f'IP:{srcip} - ConnectTime:{ConnectedTime} - DecreaseTrust(Dispersion*10):{Dispersion*10} - NowTrust:{IOTDevicesInfo[srcip]["TrustValue"]}'
                append_string_to_file(input_string , DefenseRecord)
                IOTDevicesInfo[srcip]["IOTInfoIsChanged"] = False


            for dstip, connection_count in IOTDevicesInfo[srcip]['connection_count'].items():
                if connection_count >= 5 :
                    ConnectionCountArg = 10
                    IOTDevicesInfo[srcip]["TrustValue"] -= ConnectionCountArg * connection_count
                    input_string = f'IP:{srcip} - ConnectTime:{ConnectedTime} - DecreaseTrust(connection_count*{ConnectionCountArg}):{5 * connection_count} - NowTrust:{IOTDevicesInfo[srcip]["TrustValue"]}'
                    append_string_to_file(input_string, DefenseRecord)


            # print(f"Exe Time : {NetworkTimeInfo['MECtotalExeTime']}\n\n\n\n")
            if int(NetworkTimeInfo['MECtotalExeTime']%20)<0.001 and NetworkTimeInfo['MECtotalExeTime']>20 and IOTDevicesInfo[srcip]["TrustValue"]>=60 : 
                if srcip in BlockList : 
                    return
                print(f"SrcIP:{srcip} - TrustValue Back to 100\n\n\n")
                IOTDevicesInfo[srcip]["TrustValue"] = 100
                CleanerList = 'IPS/CleanerList.txt'
                append_string_to_file(srcip, CleanerList)


            NetworkTimeInfo['NetworkTimeArray'].append(datetime.now())
            NetworkTimeInfo['MECtotalExeTime'] += (NetworkTimeInfo['NetworkTimeArray'][-1]-NetworkTimeInfo['NetworkTimeArray'][-2]).total_seconds()
            
            if IOTDevicesInfo[srcip]["TrustValue"] < 30 : 
                append_string_to_file(srcip , SuspiciousFile)
                continue



    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> IDS : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)