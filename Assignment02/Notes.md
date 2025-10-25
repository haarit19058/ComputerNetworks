# Installing mininet

Pakage manager for arch linux
yay -S mininet 

start the openswitch

### Also we need to isntall the ovs switch

sudo systemctl start ovsdb-server.service
sudo systemctl start ovs-vswitchd.service


# What are we doing exactly ??

- mininet - builds virtual network
- open vswitch ovs = the virtual switch software
- sdn controller - the brain controlling ovs


What is openwitch

Open vSwitch (OVS) is a software-based virtual switch that runs inside Linux.




# Ping issue cannot detect other hosts and devices

- By default the self.add switch do not know what to do wiht the packets.
- There fore we need a controller for switches from mininet.node that 
- Otherwise use a ovs switch that would send packet to all other connected nodes.
- Even though due to /24 dns was not able to reach host due to it was on some other subnet so i used /16 instead


# remove the mininet cache in case it is not shutdown properly
sudo mn -c


# Installing the controller in mint
sudo apt-get install openvswitch-testcontroller
sudo ln -s /usr/bin/ovs-testcontroller /usr/bin/controller



# How to give internet access to hosts

Mininet have a default nat network configuration in nat.py use it from python only it is the easiest method

# No file called /etc/network/interfaces on arch
make dummy file with following content:
auto lo
iface lo inet loopback