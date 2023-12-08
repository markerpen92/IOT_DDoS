import threading
import sys
import math
import time
import traceback
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


def SimpleDetectionSystem(IOTDevicesInfo , BlockList) : 
    SuspiciousFile = "IPS/SuspiciousList.txt"
    # print("~"*20)
    if IOTDevicesInfo == {} : 
        return
    try : 
        for srcip in IOTDevicesInfo : 
            if IOTDevicesInfo[srcip]["IOTInfoIsChanged"] == False or srcip in BlockList : 
                continue
            ConnectedTime = IOTDevicesInfo[srcip]["ConnectedTime"]
            PktAmount = IOTDevicesInfo[srcip]["PktAmount"]

            if ConnectedTime%100 < 0.001 and ConnectedTime/100 > 1 :  
                IOTDevicesInfo[srcip]["TrustValue"] -= 10

            if ConnectedTime > 0 : 
                SuspiciousLevel = (PktAmount/ConnectedTime)/200
                IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15

            elif ConnectedTime == 0 : 
                SuspiciousLevel = (PktAmount)/200
                IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15

            # To make sure is script attack or not ??
            PktAmountHistory = list(IOTDevicesInfo[srcip]['PktAmountHistory'])[:-1]
            AverageAmountEachSec = sum(PktAmountHistory) / 5.0
            Dispersion = math.exp(-1*sum(abs(AverageAmountEachSec-amount) for amount in PktAmountHistory))
            if Dispersion > 0.5 : 
                IOTDevicesInfo[srcip]["TrustValue"] -= Dispersion*10

            IOTDevicesInfo[srcip]["IOTInfoIsChanged"] = False
            
            if IOTDevicesInfo[srcip]["TrustValue"] < 30 : 
                append_string_to_file(srcip , SuspiciousFile)
                continue
                
    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f"<Error> IDS : {e}")
        print(f"Traceback: {traceback_str}")
        time.sleep(2.0)