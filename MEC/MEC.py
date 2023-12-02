'''
Intergrated All Functions by using threading (MEC Interface)
'''
import os
import netfilterqueue
import threading
import time
from functools import partial
from Forwarding import packetParse
from Measurement.MeasureConnectedTime import GetConnectedTime
from Measurement.MeasureTraffic import GetTraffic
from IDS.SimpleDetectionSys import SimpleDetectionSystem
from IPS.Iptables import Iptables

IOTDevicesInfo = {}

def ForwardpktAndGetService() : 
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    queue1 = netfilterqueue.NetfilterQueue()
    queue1.bind(1, partial(packetParse , IOTDevicesInfo=IOTDevicesInfo))
    try:
        queue1.run()  # Main loop for queue 1
    except KeyboardInterrupt : 
        print("<Error> Didnt Enter netfilterqueue")
        os.system('iptables -D FORWARD -j NFQUEUE --queue-num 1')
        queue1.unbind()

def GetIOTDevicesInfo() : 
    while 1 : 
        try : 
            # print("In Correct Function")
            GetConnectedTime(IOTDevicesInfo)
            GetTraffic(IOTDevicesInfo)
        except Exception as e :
            print(f"<Error> GetIOTDevicesInfo : {e}")
            time.sleep(2.0)
            continue


def DetectAndDefenseSys() : 
    while 1 : 
        try : 
            SimpleDetectionSystem(IOTDevicesInfo)
            Iptables()
        except Exception as e :
            print(f"<Error> DetectAndDefenseSys : {e}")
            time.sleep(2.0)
            continue

def main() : 
    os.system("sudo iptables-save > iptables.conf")
    threading.Thread(target=ForwardpktAndGetService).start()
    threading.Thread(target=GetIOTDevicesInfo).start()
    threading.Thread(target=DetectAndDefenseSys).start()

if __name__ == '__main__':
    main()