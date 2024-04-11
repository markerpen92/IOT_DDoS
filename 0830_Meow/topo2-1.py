#!/usr/bin/env python
# docker images(Checker Images), docker pull kathara/quagga (Download Images)
# Defaut accout password zebra / (meow)
 

from mininet.net import Containernet 
from mininet.cli import CLI
from mininet.link import TCLink, Link
from mininet.log import info, setLogLevel


setLogLevel('info')
net = Containernet()

# Normal-Node

USER1 = net.addHost('USER1')
ATTACKER1 = net.addHost('ATTACKER1')

USER2 = net.addHost('USER2')
ATTACKER2 = net.addHost('ATTACKER2')

# Router-Node 

MEC1 = net.addDocker('MEC1', dimage="kathara/quagga:v1.3", volumes=["/home/user/Desktop/iotMecDDos/0830_Meow/DynamicRoutingOSPF/MEC1/quagga:/etc/quagga"])
RS = net.addDocker('RS', dimage="kathara/quagga:v1.3", volumes=["/home/user/Desktop/iotMecDDos/0830_Meow/DynamicRoutingOSPF/RS/quagga:/etc/quagga"])
MEC2 = net.addDocker('MEC2', dimage="kathara/quagga:v1.3", volumes=["/home/user/Desktop/iotMecDDos/0830_Meow/DynamicRoutingOSPF/MEC2/quagga:/etc/quagga"])

# Linking the Node  

net.addLink(USER1, MEC1)
net.addLink(ATTACKER1, MEC1)

net.addLink(MEC1, RS)
net.addLink(RS, MEC2)

net.addLink(MEC2,USER2)
net.addLink(MEC2,ATTACKER2)

net.build()

# Normal-Node(Area1)  setting 

USER1.cmd("ifconfig USER1-eth0 0")
ATTACKER1.cmd("ifconfig ATTACKER1-eth0 0")

USER1.cmd("ip address add 192.168.10.1/24 dev USER1-eth0")
ATTACKER1.cmd("ip address add 192.168.20.2/24 dev ATTACKER1-eth0")

USER1.cmd("ip route add default via 192.168.10.254 dev USER1-eth0")
ATTACKER1.cmd("ip route add default via 192.168.20.254 dev ATTACKER1-eth0")

#MEC1 Setting 

MEC1.cmd("ifconfig MEC1-eth0 0") # USER1 <-> MEC1
MEC1.cmd("ifconfig MEC1-eth1 0") # Attacker <-> MEC1
MEC1.cmd("ifconfig MEC1-eth2 0") # ME1 <-> RS 

MEC1.cmd("ip addr add 192.168.10.254/24 brd + dev MEC1-eth0")
MEC1.cmd("ip addr add 192.168.20.254/24 brd + dev MEC1-eth1")
MEC1.cmd("ip addr add 140.1.1.1/24 brd + dev MEC1-eth2") 

MEC1.cmd("/etc/init.d/quagga restart") 


#RS Setting 
RS.cmd("ifconfig RS-eth0 0") #MEC1<->RS
RS.cmd("ifconfig RS-eth1 0") #MEC2<->RS

RS.cmd("ip addr add 140.1.1.2/24 brd + dev RS-eth0")  
RS.cmd("ip addr add 140.1.2.2/24 brd + dev RS-eth1") 

RS.cmd("/etc/init.d/quagga restart")


#MEC2 Setting 
MEC2.cmd("ifconfig MEC2-eth0 0") # RS <-> MEC2  
MEC2.cmd("ifconfig MEC2-eth1 0") # RS <-> USER2
MEC2.cmd("ifconfig MEC2-eth2 0") # RS <-> ATTACKER2

MEC2.cmd("ip addr add 140.1.2.1/24 brd + dev MEC2-eth0") 
MEC2.cmd("ip addr add 192.168.30.254/24 brd + dev MEC2-eth1")
MEC2.cmd("ip addr add 192.168.40.254/24 brd + dev MEC2-eth2")

MEC2.cmd("/etc/init.d/quagga restart") 

# Normal-Node(Area2)  Setting 

USER2.cmd("ifconfig USER2-eth0 0")
ATTACKER2.cmd("ifconfig ATTACKER2-eth0 0")

USER2.cmd("ip address add 192.168.30.1/24 dev USER2-eth0")
ATTACKER2.cmd("ip address add 192.168.40.2/24 dev ATTACKER2-eth0")

USER2.cmd("ip route add default via 192.168.30.254 dev USER2-eth0")
ATTACKER2.cmd("ip route add default via 192.168.40.254 dev ATTACKER2-eth0")


CLI(net)
net.stop()
