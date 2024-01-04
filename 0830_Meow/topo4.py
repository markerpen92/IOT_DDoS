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

    h1 = net.addHost('h1', ip='192.168.0.1/24')
    h2 = net.addHost('h2', ip='192.168.0.2/24')
    br1 = net.addHost('br1')
    r1 = net.addHost('r1', ip='192.168.0.254/24')
    d1 = net.addDocker('d1', ip='10.0.0.1/24', dimage="ubuntu:16.04ok1")
 
    info('*** Creating links\n')
    net.addLink(h1, br1)
    net.addLink(h2, br1)
    net.addLink(r1, br1)
    net.addLink(r1, d1)
    
    info('*** Starting network\n')
    net.start()
    d1.cmd("/etc/init.d/ssh start")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ip addr add 10.0.0.2/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    r1.cmd("iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o r1-eth1 -j MASQUERADE")
    h1.cmd("ip route add default via 192.168.0.254")
    h2.cmd("ip route add default via 192.168.0.254")
    br1.cmd("ifconfig br1-eth0 0")
    br1.cmd("ifconfig br1-eth1 0")
    br1.cmd("ifconfig br1-eth2 0")
    br1.cmd("brctl addbr br1")
    br1.cmd("brctl addif br1 br1-eth0")
    br1.cmd("brctl addif br1 br1-eth1")
    br1.cmd("brctl addif br1 br1-eth2")
    br1.cmd("ifconfig br1 up") 

 
    info('*** Running CLI\n')
    CLI(net)
 
    info('*** Stopping network')
    net.stop()
 
if __name__ == '__main__':
    setLogLevel('info')
    topology()