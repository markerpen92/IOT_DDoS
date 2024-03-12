import threading
import sys
sys.path.append("../IPS")

def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a') as file :
                file.write(input_string + '\n')
            # print(f'String Add into end of file:{filename}!')
    except Exception as e :
        print(f'Error Msg : {e}')


def SimpleDetectionSystem(IOTDevicesInfo) : 
    SuspiciousFile = "IPS/SuspiciousList.txt"
    if IOTDevicesInfo == {} : 
        return
    for srcip in IOTDevicesInfo : 
        ConnectedTime = IOTDevicesInfo[srcip]["ConnectedTime"]
        PktAmount = IOTDevicesInfo[srcip]["PktAmount"]
        if ConnectedTime%100 < 0.001 and ConnectedTime/100 > 0 :  
            IOTDevicesInfo[srcip]["TrustValue"] -= 10
        if ConnectedTime > 0 : 
            SuspiciousLevel = (PktAmount/PktAmount)/200
            IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15

        if IOTDevicesInfo[srcip]["TrustValue"] < 30 : 
            input_string = srcip
            append_string_to_file(input_string , SuspiciousFile)
            del IOTDevicesInfo[srcip]