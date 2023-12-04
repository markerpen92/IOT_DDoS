import threading
import sys
sys.path.append("../IPS")

def append_string_to_file(input_string, filename) :
    lock = threading.Lock()
    try :
        with lock : 
            with open(filename, 'a+') as file :
                file.write(input_string + '\n')
                file.close()
            # print(f'String Add into end of file:{filename}!')
    except Exception as e :
        print(f'Error Msg : {e}')


def SimpleDetectionSystem(IOTDevicesInfo) : 
    SuspiciousFile = "IPS/SuspiciousList.txt"
    # print("~"*20)
    if IOTDevicesInfo == {} : 
        return
    try : 
        for srcip in IOTDevicesInfo : 
            if IOTDevicesInfo[srcip]["IOTInfoIsChanged"] == False : 
                # time.sleep(0.1)
                continue
            # if IOTDevicesInfo[srcip]["TrustValue"] < 30 : 
            #     # print("=======    5    =======\n\n\n")
            #     append_string_to_file(srcip , SuspiciousFile)
            #     continue
            ConnectedTime = IOTDevicesInfo[srcip]["ConnectedTime"]
            PktAmount = IOTDevicesInfo[srcip]["PktAmount"]
            if ConnectedTime%100 < 0.001 and ConnectedTime/100 > 1 :  
                # print("@@@@@@@   1    @@@@@@@\n\n\n")
                IOTDevicesInfo[srcip]["TrustValue"] -= 10
            if ConnectedTime > 0 : 
                # print("+++++++    2    +++++++\n\n\n")
                SuspiciousLevel = (PktAmount/ConnectedTime)/200
                IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15
            elif ConnectedTime == 0 : 
                # print("-------    3    -------\n\n\n")
                SuspiciousLevel = (PktAmount)/200
                IOTDevicesInfo[srcip]["TrustValue"] -= SuspiciousLevel*15

            IOTDevicesInfo[srcip]["IOTInfoIsChanged"] = False
            
            # print("*******    4    *******\n\n\n")
            if IOTDevicesInfo[srcip]["TrustValue"] < 30 : 
                # print("=======    5    =======\n\n\n")
                append_string_to_file(srcip , SuspiciousFile)
                continue
    except Exception as e : 
        print(f"<Error> MeasureTraffic : {e}")
        time.sleep(2.0)