'''
Intergrated All Functions by using threading (MEC Interface)
'''
import os
import netfilterqueue
import threading
import time
from Forwarding import packetParse
from MeasureConnectedTime import GetConnectedTime
from MeasureTraffic import GetTraffic
from functools import partial


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
        pass


def main() : 
    os.system("sudo iptables-save > iptables.conf")
    threading.Thread(target=ForwardpktAndGetService).start()
    threading.Thread(target=GetIOTDevicesInfo).start()
    threading.Thread(target=DetectAndDefenseSys).start()

if __name__ == '__main__':
    main()