'''
Intergrated All Functions by using threading (MEC Interface)
'''
import os
import netfilterqueue
import threading
import time
import signal
from functools import partial
from Forwarding import packetParse
from Measurement.MeasureConnectedTime import GetConnectedTime
from Measurement.MeasureTraffic import GetTraffic
from IDS.SimpleDetectionSys import SimpleDetectionSystem
from IPS.Iptables import Iptables

IOTDevicesInfo = {}
BlockList = []

def ForwardpktAndGetService() : 
    queue1 = netfilterqueue.NetfilterQueue()
    queue1.bind(1, partial(packetParse , IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList))
    try:
        queue1.run()  # Main loop for queue 1
    except KeyboardInterrupt : 
        print("<Error> Didnt Enter netfilterqueue")
        os.system('iptables -D FORWARD -j NFQUEUE --queue-num 1')
        queue1.unbind()

def GetIOTDevicesInfo() : 
    while 1 : 
        try : 
            GetConnectedTime(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList)
            GetTraffic(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList)
        except Exception as e :
            print(f"<Error> GetIOTDevicesInfo : {e}")
            time.sleep(2.0)
            continue


def DetectAndDefenseSys() : 
    while 1 : 
        # pass
        try : 
            SimpleDetectionSystem(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList)
            Iptables(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList)
            time.sleep(1.0)
        except Exception as e :
            print(f"<Error> DetectAndDefenseSys : {e}")
            time.sleep(2.0)
            continue

def main() : 
    os.system("sudo iptables-save > iptables.conf")
    threading.Thread(target=ForwardpktAndGetService).start()
    threading.Thread(target=GetIOTDevicesInfo).start()
    threading.Thread(target=DetectAndDefenseSys).start()

def EndMEC(sig , frame) : 
    try : 
        fileAPath = './Measurement/Record/MeasureConnectedTime.txt'
        fileBPath = './Measurement/Record/MeasureCPUOccupy.txt'
        fileCPath = './Measurement/Record/MeasureTraffic.txt'
        with open(fileAPath , 'w') as fileA : 
            fileA.write('')
            fileA.close()
            print(f'\nClean file-{fileAPath}')

        with open(fileBPath , 'w') as fileB : 
            fileB.write('')
            fileB.close()
            print(f'\nClean file-{fileBPath}')

        with open(fileCPath , 'w') as fileC : 
            fileC.write('')
            fileC.close()
            print(f'\nClean file-{fileCPath}')

        cmd = "sudo iptables -F"
        os.system(cmd)
        print("\n<End Msg> Clean Iptables || End of MEC Exiting...")
        exit()
    except Exception as e :
            print(f"<Error> EndMEC : {e}")
            exit()

if __name__ == '__main__' :
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    main()
    signal.signal(signal.SIGINT, EndMEC)