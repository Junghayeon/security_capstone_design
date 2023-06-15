import requests
from scapy.all import *


def check_ip_safety(ip_address, detect, suspect):
    url = f"https://api.criminalip.io/v1/ip/summary?ip={ip_address}"
    headers = {
        "x-api-key": "1EonWdaxgPqvwN2WfP6elqLZGIhs5UlJdRjIMFsEVgHBA2L3VpIFfYJl5BJo"
    }
    response = requests.get(url, headers=headers)

    print(response.text)

    if response.status_code == 200:
        data = response.json()
        score = data.get("score", {})
        inbound = score.get("inbound")
        outbound = score.get("outbound")

        if inbound is not None and outbound is not None:
            if inbound >= 4 or outbound >= 4:
                print(f"{ip_address} unsafe.")
                detect[ip_address] = 'unsafe ip'


def check_port_safety(ports, detect, ip_address):
    known_ports = {20, 21, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389}
    unsafe_ports = [port for port in ports if port not in known_ports]
    if unsafe_ports:
        detect[ip_address] = 'unsafe port'
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

                ip_list = [src_ip, dst_ip]

                for ip_address in ip_list:
                    check_ip_safety(ip_address, detect, suspect)

                    if packet.haslayer(TCP):
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        ports = [src_port, dst_port]
                        print(f"Port numbers for {ip_address}: {ports}")
                        check_port_safety(ports, detect, ip_address)

                    elif packet.haslayer(UDP):
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        ports = [src_port, dst_port]
                        print(f"Port numbers for {ip_address}: {ports}")
                        check_port_safety(ports, detect, ip_address)

    except Exception as err:
        print(err)
    finally:
        print("finally")
        print(f"detect: {detect}")
        print(f"suspect: {suspect}")
        data['detect'] = detect
        return data
       
