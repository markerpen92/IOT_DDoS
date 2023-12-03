import threading
import sys
sys.path.append("../IPS")

def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a') as file :
                file.write(input_string + '\n')
                file.close()
            # print(f'String Add into end of file:{filename}!')
    except Exception as e :
        print(f'Error Msg : {e}')


def SimpleDetectionSystem(IOTDevicesInfo) : 
    SuspiciousFile = "IPS/SuspiciousList.txt"
    if IOTDevicesInfo == {} : 
        return
    for srcip in IOTDevicesInfo : 
        if IOTDevicesInfo[srcip]["IOTInfoIsChanged"] == False : 
            time.sleep(0.1)
            return
        ConnectedTime = IOTDevicesInfo[srcip]["ConnectedTime"]
        PktAmount = IOTDevicesInfo[srcip]["PktAmount"]
        if ConnectedTime%100 < 0.001 and ConnectedTime/100 > 0 :  
            IOTDevicesInfo[srcip]["TrustValue"] -= 10
        if ConnectedTime > 0 : 
            SuspiciousLevel = (PktAmount/PktAmount)/200
            IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15

        IOTDevicesInfo[srcip]["IOTInfoIsChanged"] = False

        if IOTDevicesInfo[srcip]["TrustValue"] < 30 : 
            input_string = srcip
            append_string_to_file(input_string , SuspiciousFile)
            del IOTDevicesInfo[srcip]