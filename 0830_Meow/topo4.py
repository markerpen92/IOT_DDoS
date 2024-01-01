#!/usr/bin/python
from mininet.net import Containernet
from mininet.node import Docker
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Link
 
def topology():
 
    "Create a network with some docker containers acting as hosts."
    net = Containernet()
 
    info('*** Adding hosts\n')
    Attacker = net.addHost('Attacker', ip='192.168.0.1/24')
    NormalIoT = net.addHost('NormalIoT', ip='192.168.0.2/24')
    b1 = net.addHost('b1')
    MEC = net.addHost('MEC', ip='192.168.0.254/24')
    RS = net.addDocker('RS', ip='10.0.0.1/24', dimage="ubuntu:16.04ok1")
 
    info('*** Creating links\n')
    net.addLink(Attacker, b1)
    net.addLink(NormalIoT, b1)
    net.addLink(MEC, b1)
    net.addLink(MEC, RS)
    
    info('*** Starting network\n')
    net.start()
    RS.cmd("/etc/init.d/ssh start")
    MEC.cmd("ifconfig MEC-eth1 0")
    MEC.cmd("ip addr add 10.0.0.2/24 brd + dev MEC-eth1")
    MEC.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    MEC.cmd("iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o MEC-etAttacker -j MASQUERADE")
    Attacker.cmd("ip route add default via 192.168.0.254")
    NormalIoT.cmd("ip route add default via 192.168.0.254")
    b1.cmd("ifconfig b1-eth0 0")
    b1.cmd("ifconfig b1-eth1 0")
    b1.cmd("ifconfig b1-eth2 0")
    b1.cmd("brctl addbr b1")
    b1.cmd("brctl addif b1 b1-eth0")
    b1.cmd("brctl addif b1 b1-eth1")
    b1.cmd("brctl addif b1 b1-eth2")
    b1.cmd("ifconfig b1 up") 
 
    info('*** Running CLI\n')
    CLI(net)
 
    info('*** Stopping network')
    net.stop()
 
if __name__ == '__main__':
    setLogLevel('info')
    topology()