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
                return line
            else : 
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
    if BadIP == None and GoodIP == None : 
        time.sleep(1.0)
        return None
    print(f"Ban Bad User : {BadIP}")
    BlockList.append(BadIP)
    print(IOTDevicesInfo[BadIP]['TrustValue'])
    del IOTDevicesInfo[BadIP]
    cmd = f'sudo iptables -t filter -I FORWARD -j DROP -s {BadIP}'
    print(f"IOTDevicesInfo : {IOTDevicesInfo} || CMD : {cmd}")
    os.system(cmd)

    return BadIP , GoodIP 








def GetRecordToTrain(BadIP=None , GoodIP=None) : 
    if BadIP == None and GoodIP == None : 
        return
    elif BadIP != None : 
        BadRole = 'BAD '
        BadTargetIP = BadIP
    elif GoodIP!= None :
        GoodRole = 'GOOD '
        GoodTargetIP = GoodIP

    filename = "IPS/record.txt"

    line_num = 0
    OneRecord = ''
    while OneRecord != None : 
        OneRecord = ReadOneRecord(filename , line_num)
        patterns = OneRecord.split(' ')

        if BadTargetIP == patterns[0] : 
            record = RemoveOneRecord(filename , line_num)
            record = BadRole + record
            TraingFile = 'IDS/TrainingList.txt'
            WriteRecordIntoFile(TraingFile , record)
        elif GoodTargetIP == patterns[0] :
            record = RemoveOneRecord(filename , line_num)
            record = GoodRole + record
            TraingFile = 'IDS/TrainingList.txt'
            WriteRecordIntoFile(TraingFile , record)
        
        line_num += 1