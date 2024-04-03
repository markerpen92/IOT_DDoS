'''
Intergrated All Functions by using threading (MEC Interface)
'''
import os
import netfilterqueue
import threading
import time
import signal
import argparse
import traceback

from collections import deque
from datetime import datetime
from functools import partial


from Forwarding import packetParse


from Measurement.MeasureConnectedTime import GetConnectedTime
from Measurement.MeasureTraffic import GetTraffic


from IDS.SimpleDetectionSys import SimpleDetectionSystem
from IDS.CNNmodel import CNN_Model


from IPS.Iptables import Iptables
from IPS.Iptables import GetRecordToTrain



# parser = argparse.ArgumentParser(description='client ip')

# parser.add_argument('--ip', type=str, default='192.168.0.1')
# self_ip = parser.parse_args().ip

Pred_model = CNN_Model(pkt_features=10)
Tran_model = CNN_Model(pkt_features=10)

NetworkTimeInfo = {
    'NetworkTimeArray' : deque([datetime.now()] , maxlen=2) ,  # real time array
    'MECtotalExeTime'  : 0.0    # 0.0 sec
}

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






def DetectSys() : 
    while 1 : 
        try : 
            threading.Thread(target=Pred_model.PredictModel , args=(Tran_model,)).start()
            threading.Thread(target=Tran_model.TrainingModel , args=(Pred_model,)).start()
        except Exception as e : 
            print(f"<Error> DetectSys : {e}")
            time.sleep(2.0)
            continue






def DefenseSys() : 
    while 1 : 
        # pass
        try : 
            SimpleDetectionSystem(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList , NetworkTimeInfo=NetworkTimeInfo)
            BadIP , GoodIP = Iptables(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList)
            GetRecordToTrain(BadIP=BadIP , GoodIP=GoodIP)
            #time.sleep(0.5)
        except Exception as e :
            #print(f"<Error> DetectAndDefenseSys : {e}")#n0 vul3 ????????????
            
            traceback_str = traceback.format_exc()
            print(f"<Error> : {e}")
            print(f"Traceback: {traceback_str}")
            time.sleep(2.0)
   
            continue






def main() : 
    os.system("sudo iptables-save > iptables.conf")
    threading.Thread(target=ForwardpktAndGetService).start()
    threading.Thread(target=GetIOTDevicesInfo).start()
    #threading.Thread(target=DetectSys).start() # CNN
    threading.Thread(target=DefenseSys).start()



def EndMEC(sig , frame) : 

    try : 
        filepathes = [
            './Measurement/Record/MeasureConnectedTime.txt' , 
            './Measurement/Record/MeasureCPUOccupy.txt' , 
            './Measurement/Record/MeasureTraffic.txt' , 
            './IDS/TrainingList.txt',
            './IDS/record.txt',
            './IPS/record.txt',
            './IPS/SuspiciousList.txt',
            './IPS/CleanerList.txt'
        ]

        for filepath in filepathes : 
            with open(filepath , 'w') as file : 
                file.write('')
                file.close()
                print(f'\nClean file-{filepath}')


        cmd = "sudo iptables -F"
        os.system(cmd)
        print("\n<End Msg> Clean Iptables || End of MEC Exiting...")
        exit()


    except Exception as e : 
            print(f"<Error> EndMEC : {e}")
            exit()


def GetCNNmodel() : 
    return Pred_model





if __name__ == '__main__' :
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    main()
    signal.signal(signal.SIGINT, EndMEC)