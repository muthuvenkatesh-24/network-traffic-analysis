from scapy.all import *

pcap_file = "checksum_capture.pcapng"
packets = rdpcap(pcap_file)

def validate_ip_checksum(pkt):
    if IP in pkt:
        original = pkt[IP].chksum
        del pkt[IP].chksum
        recalculated = IP(bytes(pkt[IP])).chksum
        return original == recalculated
    return None

def validate_tcp_checksum(pkt):
    if IP in pkt and TCP in pkt:
        original = pkt[TCP].chksum
        del pkt[TCP].chksum
        recalculated = TCP(bytes(pkt[TCP])).chksum
        return original == recalculated
    return None

def validate_udp_checksum(pkt):
    if IP in pkt and UDP in pkt:
        original = pkt[UDP].chksum
        del pkt[UDP].chksum
        recalculated = UDP(bytes(pkt[UDP])).chksum
        return original == recalculated
    return None

print("CHECKSUM VALIDATION USING SCAPY")
print("--------------------------------")

for i, pkt in enumerate(packets, start=1):
    if IP in pkt:
        ip_ok = validate_ip_checksum(pkt)
        tcp_ok = validate_tcp_checksum(pkt)
        udp_ok = validate_udp_checksum(pkt)

        print(f"Packet {i}:")
        if ip_ok is not None:
            print(f"  IP Checksum Valid  : {ip_ok}")
        if tcp_ok is not None:
            print(f"  TCP Checksum Valid : {tcp_ok}")
        if udp_ok is not None:
            print(f"  UDP Checksum Valid : {udp_ok}")
