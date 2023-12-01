'''
Intergrated All Functions by using threading
'''
import os
import netfilterqueue
from Forwarding import packetParse
from MeasureConnectedTime import GetConnectedTime
import threading

IOTDevicesInfo = {}


def ForwardpktAndGetService() : 
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    queue1 = netfilterqueue.NetfilterQueue()
    queue1.bind(1, packetParse)
    try:
        queue1.run()  # Main loop for queue 1
    except KeyboardInterrupt : 
        print("<Error> Didnt Enter netfilterqueue")
        os.system('iptables -D FORWARD -j NFQUEUE --queue-num 1')
        queue1.unbind()

def GetIOTDevicesInfo() : 
    while 1 : 
        GetConnectedTime(IOTDevicesInfo)


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