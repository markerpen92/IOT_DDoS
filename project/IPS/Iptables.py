import os

def ReadSuspiciousFile(filename) : 
    with open(filename , 'r+') as file : 
        lines = file.readlines()
        if lines : 
            FirstLine = lines.pop(0)
            file.seek(0)
            file.truncate()
            # print("Delete first line")
            file.close()
            return FirstLine
        else : 
            # print(f"<No line to read>{file} has no record")
            return

def Iptables() : 
    BadIP = ReadSuspiciousFile(filename)
    cmd = f'sudo iptables -t filter -A INPUT -j DROP -s {BadIP}'
    os.system(cmd)