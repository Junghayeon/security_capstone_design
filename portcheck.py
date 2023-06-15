import requests
from scapy.all import *


def check_port_safety(ports, detect, ip_address):
    known_ports = {20, 21, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389}
    unsafe_ports = [port for port in ports if port not in known_ports]
    if unsafe_ports:
        detect[ip_address] = unsafe_ports
        print(f"Unsafe ports detected for {ip_address}: {unsafe_ports}")


def pcap_read(filepath):
    packets = rdpcap(filepath)
    data = dict()
    detect = dict()
    suspect = dict()
    data['total_pks'] = len(packets)

    try:
        for packet in packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if packet.haslayer(TCP):
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    ports = [src_port, dst_port]
                    print(f"Port numbers for {src_ip}: {ports}")
                    check_port_safety(ports, detect, src_ip)

                elif packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    ports = [src_port, dst_port]
                    print(f"Port numbers for {src_ip}: {ports}")
                    check_port_safety(ports, detect, src_ip)

    except Exception as err:
        print(err)
    finally:
        print("finally")
        print(f"detect: {detect}")
        print(f"suspect: {suspect}")
        data['detect'] = detect
        return data

