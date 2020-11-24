#!/usr/bin/python

from sys import argv
import random
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel
from time import sleep
#from mininet.cli import CLI

c0 = RemoteController('c0', ip='127.0.0.1', port=6633)

random.seed(2)

class Tp1Topo(Topo):

    def build(self, n=3, m=3):
        frontSwitch = self.addSwitch('s1')

        for i in range(n):
            host = self.addHost('h%s' % (i+1))
            self.addLink(host, frontSwitch)

        for i in range(m):
            web = self.addHost('web%s' % (i+1), ip='10.0.0.1%s/8' % (i+1), mac='00:00:00:00:00:1%s' % (i+1))
            self.addLink(web, frontSwitch)

def test_range(n, min, max):
    if n in range(min, max+1):
        return True

    return False

def test(hosts, servers):
    topo = Tp1Topo(n=hosts, m=servers)
    net = Mininet(topo=topo, switch=OVSSwitch, autoSetMacs=True, controller=None)

    net.addController(c0)

    for i in range(servers):
        w = net.get('web%s' % (i+1))
        w.cmd('iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP')
        sleep(1)
        w.cmd('tshark -i web%s-eth0' % (i+1) + ' -w /tmp/web%s.pcapng &' % (i+1))

    net.start()

    sleep(2)
    for i in range(hosts):
        h = net.get('h%s' % (i+1))
        rnd_src = random.randint(0,1)
        rnd_dst = random.randint(1,servers)
        print(rnd_src,rnd_dst)
        #h.cmd('iperf -u -p 80 -c 10.0.0.11 -b %sM -t 60 &' % rnd)
        if rnd_src:
            print(h.cmd('nmap -sT -Pn --scan-delay 1 -F 10.0.0.1'+str(rnd_dst)))
            #print(h.cmd('nmap -sU -p 123,161-170 10.0.0.1'+str(rnd_dst)))
        sleep(1)

    #CLI(net) # launch cli to be able to get info from the network elements such as dpctl dumpflows in the switch
    sleep(50)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')

    if len(argv) != 3:
        print 'Usage: %s <nb_hosts> <nb_servers>'
        exit(1)

    hosts,servers = argv[1:3]

    if not test_range(int(hosts), 1, 10) or not test_range(int(servers), 1, 10):
        print 'Usage: <nb_hosts> and <nb_servers> should be in [1:10]'
        exit(1)

    test(int(hosts), int(servers))
