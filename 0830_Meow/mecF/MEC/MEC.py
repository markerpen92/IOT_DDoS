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
from IDS.CleanerDataBase import JsonFile


from IPS.Iptables import Iptables
from IPS.Iptables import GetRecordToTrain



ModelPath = './IDS/model.pth'

Pred_model = CNN_Model(pkt_features=4)
Tran_model = CNN_Model(pkt_features=4)

if os.path.exists(ModelPath) : 
    Pred_model.UpdateModel(ModelPath)
    print('Predict-Model Loaded Successfully')
    Tran_model.UpdateModel(ModelPath)
    print('Tran-Model Loaded Successfully')




CleanerDB_Path = './IDS/CleanerDataBase.json'
CleanerDB = None

if os.path.exists(CleanerDB_Path) : 
    CleanerDB = JsonFile(CleanerDB_Path)
    print('Cleaner.json Loaded Successfully')
else : 
    print('Cleaner.json Loaded Failled')





NetworkTimeInfo = {
    'NetworkTimeArray' : deque([datetime.now()] , maxlen=2) ,  # real time array
    'MECtotalExeTime'  : 0.0    # 0.0 sec
}

IOTDevicesInfo = {}
BlockList = set()






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






def DetectSys_Predict() : 
    while 1 : 
        try : 
            Pred_model.PredictModel(training_model=Tran_model , BlockList=BlockList)
            # Tran_model.TrainingModel(testing_model=Pred_model)
            
        except Exception as e : 
            # print(f"<Error> DetectSys_Predict : {e}")
            time.sleep(0.5)
            continue

def DetectSys_Train() : 
    while 1 : 
        try : 
            # Pred_model.PredictModel(training_model=Tran_model)
            time.sleep(25.0)
            Tran_model.TrainingModel(testing_model=Pred_model)
            # time.sleep(30.0)
            
        except Exception as e : 
            #print(f"<Error> DetectSys_Train : {e}")
            time.sleep(2.0)
            continue






def DefenseSys() : 
    while 1 : 
        # pass
        try : 
            # SimpleDetectionSystem(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList , NetworkTimeInfo=NetworkTimeInfo)
            BadIP , GoodIP = Iptables(IOTDevicesInfo=IOTDevicesInfo , BlockList=BlockList)
            GetRecordToTrain(BadIP=BadIP , GoodIP=GoodIP , BlockList=BlockList , CleanList=CleanerDB.Cleaners)
            #time.sleep(0.5)
        except Exception as e :
            
            traceback_str = traceback.format_exc()
            print(f"<IDS Error> : {e}")
            print(f"Traceback: {traceback_str}")
            time.sleep(2.0)
   
            continue





def CheckFileUpdate() : 
    while 1 :
        try : 
            CleanerDB.Read()
        except Exception as e :
            print(f"<Error> CheckFileUpdate : {e}")
            time.sleep(2.0)
            continue





def main() : 
    os.system("sudo iptables-save > iptables.conf")
    threading.Thread(target=ForwardpktAndGetService).start()
    threading.Thread(target=GetIOTDevicesInfo).start()
    threading.Thread(target=DetectSys_Predict).start() # CNN45646
    threading.Thread(target=DetectSys_Train).start()   # CNN54732
    threading.Thread(target=DefenseSys).start()
    threading.Thread(target=CheckFileUpdate).start()



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
            './IPS/CleanerList.txt',
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





if __name__ == '__main__' :
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    main()
    signal.signal(signal.SIGINT, EndMEC)