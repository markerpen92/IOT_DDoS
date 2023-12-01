import re

def ReadRecord(filename) : 
    with open(filename , 'r+') as file : 
        lines = file.readlines()
        if lines : 
            FirstLine = lines.pop(0)
            file.seek(0)
            file.writelines(lines)
            file.truncate()
            return FirstLine
        else : 
            print(f"<No line to read>{file} has no record")

def AnalysisRecord(record) : 
    pattern = r"\[Src IP\]-(?P<SrcIP>[\d\.]+)"

    match = re.search(pattern, record)
    if match:
        src_ip = match.group("SrcIP")
        print("Src IP:", src_ip)
        return src_ip
    return None

def GetTraffic(IOTDevicesInfo) : 
    pass