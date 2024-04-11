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
    lines_seen = set()
    with open(filename , 'r+') as file :
        lines = file.readlines()
        file.seek(0)
        lines.append(record)
        file.truncate()

        for line in lines:
            if line not in lines_seen:
                file.write(line)
                lines_seen.add(line)
        file.close()



def Iptables(IOTDevicesInfo , BlockList) : 
    sus_filename = "IPS/SuspiciousList.txt"
    cln_filename = "IPS/CleanerList.txt"

    BadIP = RemoveOneRecord(sus_filename , 0)
    GoodIP = RemoveOneRecord(cln_filename , 0)

    if BadIP == None and GoodIP == None : 
        time.sleep(1.0)
        return None ,None

    if BadIP != None : 
        print(f"Ban Bad User : {BadIP}")
        BlockList.add(BadIP)
        if type(BadIP) == str : 
            BadIP = BadIP.replace('\n','')  #fix IP./r error!

        try : 
            del IOTDevicesInfo[BadIP]
        except Exception as e :
            time.sleep(0.5)
            return
        cmd = f'sudo iptables -t filter -I FORWARD -j DROP -s {BadIP}'
        print(f"IOTDevicesInfo : {IOTDevicesInfo} || CMD : {cmd}")
        os.system(cmd)
        
    if GoodIP != None : 
        GoodIP = GoodIP.replace('\n','')  #fix IP./r error!

    return BadIP , GoodIP 



def GetRecordToTrain(BadIP=None , GoodIP=None , BlockList=None , CleanList=None):
    GoodTargetIP =None 
    BadTargetIP =None
    BadRole = None
    GoodRole = None

    if BadIP == None and GoodIP == None : 
        return
    elif BadIP != None : 
        print(f'BadIP : {BadIP}')
        BadRole = 'BAD '
        BadTargetIP = BadIP
    elif GoodIP!= None and GoodIP not in BlockList :
        print(f'GoodIP : {GoodIP}')
        GoodRole = 'GOOD '
        GoodTargetIP = GoodIP

    filename = "./IPS/record.txt"
    line_num = 0
    OneRecord = ''

    while OneRecord != None : 

        try: 
            OneRecord = ReadOneRecord(filename , line_num)
            if OneRecord == None : 
                return
            patterns = OneRecord.split(' ')
            
            if  BadTargetIP == patterns[0] or (patterns[0] in BlockList) :
                record = RemoveOneRecord(filename , line_num)

                record_patterns = record.split(' ')

                if record_patterns in CleanList : 
                    return
                else : 
                    record = BadRole + record
                    TraingFile = 'IDS/TrainingList.txt'
                    WriteRecordIntoFile(TraingFile , record)
                    if BadTargetIP not in BlockList : 
                        BlockList.add(BadTargetIP)

                # condiction_count = 0
                # if record_patterns[0] == 0 : #window size
                #     pass
                # if record_patterns[1] == 1 : #keep alive
                #     condiction_count += 1
                # if record_patterns[2] == 1 : #\r\n or not
                #     condiction_count += 1
                # if record_patterns[3] != 0 : # content length
                #     condiction_count += 1
                # if condiction_count >= 2 : 
                #     record = BadRole + record
                #     TraingFile = 'IDS/TrainingList.txt'
                #     WriteRecordIntoFile(TraingFile , record)
                #     if BadTargetIP not in BlockList : 
                #         BlockList.add(BadTargetIP)

            elif GoodTargetIP == patterns[0] and (GoodTargetIP not in BlockList) :
                record = RemoveOneRecord(filename , line_num)
                record = GoodRole + record
                TraingFile = 'IDS/TrainingList.txt'
                WriteRecordIntoFile(TraingFile , record)
        
            line_num += 1
            time.sleep(0.1)

        except Exception as e :
            # print(f"<Error> GetRecordToTrain-While : {e}")
            time.sleep(0.5)
            return 