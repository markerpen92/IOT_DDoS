import os
import time

# Main function : Iptables

def ReadSuspiciousFile(filename) : 
    with open(filename , 'r+') as file : 
        lines = file.readlines()
        if lines : 
            FirstLine = lines.pop(0)
            FirstLine = FirstLine.rstrip('\n')
            file.seek(0)
            file.writelines(lines)
            file.truncate()
            # print("Delete first line")
            file.close()
            return FirstLine
        else : 
            # print(f"<No line to read>{file} has no record")
            return

def Iptables(IOTDevicesInfo) : 
    filename = "IPS/SuspiciousList.txt"
    BadIP = ReadSuspiciousFile(filename)
    if BadIP == None : 
        time.sleep(2.0)
        return
    print(f"Ban Bad User : {BadIP}")
    del IOTDevicesInfo[BadIP]
    cmd = f'sudo iptables -t filter -I FORWARD -j DROP -s {BadIP}'
    print(f"IOTDevicesInfo : {IOTDevicesInfo} || CMD : {cmd}")
    os.system(cmd)