#!/bin/bash/python3
from mininet.net import Containernet
from mininet.node import Docker
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Link

def topology():
    "create network with container"
    net = Containernet()

    info("adding hosts")
    h1 = net.addHost("h1", ip="192.168.0.1/24")
    r1 = net.addHost("r1", ip="192.168.0.254/24") #etho 0 setting 
    d1 = net.addDocker("d1", ip="10.0.0.1/24", dimage="ubuntu:16.04ok1")

    info("connenting each hosts") #ethID -> sequence
    net.addLink(h1,r1)
    net.addLink(r1,d1)


    info("start network and setting node configuration")
    net.start()
    #start d1 ssh service 
    d1.cmd("/etc/init.d/ssh start")
    #Router Setting
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ip addr add 10.0.0.2/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/if_forward")
    r1.cmd("iptable -t nat -A POSTROUTING -s 192.168.0.0/24 -o r1-eth1 -j MASQUERADE")
    h1.cmd("ip route add default via 192.168.0.254")


    info("running CLI")
    CLI(net)
    info("stop Network")
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    topology()
