import re
import os
import time
import threading

# Main function : Iptables

def ReadSuspiciousFile(filename) : 
    file_lock = threading.Lock()
    with file_lock :
        with open(filename , 'r+') as file : 
            lines = file.readlines()
            if lines : 
                FirstLine = lines.pop(0)
                FirstLine = FirstLine.rstrip('\n')
                file.seek(0)
                file.writelines(lines)
                file.truncate()
                file.close()
                return FirstLine
            else : 
                return



def ReadOneRecord(filename , lineNum) : 
    
    file_lock = threading.Lock()
    with file_lock : 
        with open(filename , 'r+') as file :
            lines = file.readlines()
            
            if lines : 
                line = lines[lineNum]
                file.close()
                return line
            else : 
                return None
    


def RemoveOneRecord(filename , lineNum) : 
    print("start-1")
    file_lock = threading.Lock()
    with file_lock : 
        with open(filename , 'r+') as file :
            lines = file.readlines()
        
            if lines : 
                line = lines.pop(lineNum)
                file.seek(0)
                file.writelines(lines)
                file.truncate()
                file.close()
                print("end-1")
                return line
            else : 
                print("end-2")
                return None  
        


def WriteRecordIntoFile(filename , record) : 
    
    with open(filename , 'r+') as file :
        lines = file.readlines()
        lines.append(record)
        
        file.writelines(lines)
        file.truncate()
        file.close()



def Iptables(IOTDevicesInfo , BlockList) : 
    sus_filename = "IPS/SuspiciousList.txt"
    cln_filename = "IPS/CleanerList.txt"
    # BadIP = ReadSuspiciousFile(filename)
    BadIP = RemoveOneRecord(sus_filename , 0)
    GoodIP = RemoveOneRecord(cln_filename , 0)
    print(f'BadIP : {BadIP} || GoodIP : {GoodIP}')
    if BadIP == None and GoodIP == None : 
        time.sleep(1.0)
        return None ,None
    if BadIP != None : 
            
        print(f"Ban Bad User : {BadIP}")
            
        BlockList.append(BadIP)
        if type(BadIP) == str : 
            BadIP = BadIP.replace('\n','')  #fix IP./r error!
        print(IOTDevicesInfo[BadIP]['TrustValue'])
        del IOTDevicesInfo[BadIP]
        cmd = f'sudo iptables -t filter -I FORWARD -j DROP -s {BadIP}'
        print(f"IOTDevicesInfo : {IOTDevicesInfo} || CMD : {cmd}")
        os.system(cmd)
    if GoodIP != None : 
        GoodIP = GoodIP.replace('\n','')  #fix IP./r error!

    return BadIP , GoodIP 



def GetRecordToTrain(BadIP=None , GoodIP=None):
    #print(f"BadIP : {BadIP} || GoodIP : {GoodIP}")
    GoodTargetIP =None 
    BadTargetIP =None
    BadRole = None
    GoodRole = None

    if BadIP == None and GoodIP == None : 
        print("retrunnnnn1")
        return
    elif BadIP != None : 
        print(f'BadIP : {BadIP}')
        BadRole = 'BAD '
        BadTargetIP = BadIP
    elif GoodIP!= None :
        print(f'GoodIP : {GoodIP}')
        GoodRole = 'GOOD '
        GoodTargetIP = GoodIP
    print("Reading file :./IPS/record.txt")
    filename = "./IPS/record.txt"
    line_num = 0
    OneRecord = ''

    print(f'BadGetIP : {BadTargetIP} || GoodIP : {GoodTargetIP}')
    while OneRecord != None : 
        try: 
            OneRecord = ReadOneRecord(filename , line_num)
            if OneRecord == None : 
                return
            patterns = OneRecord.split(' ')
            if  BadTargetIP == patterns[0]:
                record = RemoveOneRecord(filename , line_num)
                print(f'record : {record}')
                record = BadRole + record
                TraingFile = 'IDS/TrainingList.txt'
                WriteRecordIntoFile(TraingFile , record)
                print("Success write into TrainingList.txt")
            elif GoodTargetIP == patterns[0] :
                record = RemoveOneRecord(filename , line_num)
                record = GoodRole + record
                print(f'record : {record}')
                TraingFile = 'IDS/TrainingList.txt'
                print(f'Sucdess write into TrainingList.txt - GOOOOOOOOOOOOOOOOOOOOD')
                WriteRecordIntoFile(TraingFile , record)
            else:
                print(patterns[0])
        
            line_num += 1
            time.sleep(0.1)
        except Exception as e :
            print(f"<Error> while : {e}")
            time.sleep(0.5)
            return 