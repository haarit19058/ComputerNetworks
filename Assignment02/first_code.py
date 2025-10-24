#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import Controller
# import graphviz

class CustomTopo(Topo):
    def build(self):
        # --- Hosts ---
        h1 = self.addHost('h1', ip='10.0.0.1/16')
        h2 = self.addHost('h2', ip='10.0.0.2/16')
        h3 = self.addHost('h3', ip='10.0.0.3/16')
        h4 = self.addHost('h4', ip='10.0.0.4/16')

        # --- Switches ---
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # --- Links Host ↔ Switch ---
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')

        # --- Switch ↔ Switch ---
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')

        # --- Optional DNS host ---
        dns = self.addHost('dns', ip='10.0.2.0/16')
        self.addLink(s2, dns, bw=100, delay='1ms')

        # # --- Optional Graphviz visualization ---
        # g = graphviz.Digraph('G', filename='topology.gv', format='png')
        # for host in [h1, h2, h3, h4, dns]:
        #     g.node(host, shape='circle', style='filled', color='lightblue', label=host)
        # for sw in [s1, s2, s3, s4]:
        #     g.node(sw, shape='square', style='filled', color='orange', label=sw)
        # g.edge('h1', 's1', label='2ms,100Mbps')
        # g.edge('h2', 's2', label='2ms,100Mbps')
        # g.edge('h3', 's3', label='2ms,100Mbps')
        # g.edge('h4', 's4', label='2ms,100Mbps')
        # g.edge('s1', 's2', label='5ms,100Mbps')
        # g.edge('s2', 's3', label='8ms,100Mbps')
        # g.edge('s3', 's4', label='10ms,100Mbps')
        # g.edge('s2', 'dns', label='1ms,100Mbps')
        # g.render(view=False)
        # g.save()


def run():
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    net.start()

    print("\n*** Testing connectivity among all hosts ***\n")
    net.pingAll()

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
