# Network Traffic Analysis

This repository contains programs and documentation for analyzing network traffic and validating checksums.

## Experiment: Checksum Validation

### Method 1 – Wireshark Checksum Validation
Checksums were validated using Wireshark for the following protocols:
- Ethernet
- IP (IPv4)
- ICMP
- TCP
- UDP
- TLS

### Method 2 – Manual Checksum Calculation
Manual checksum calculation was performed for one protocol to demonstrate the checksum computation process in detail.

### Method 3 – Scapy Based Checksum Validation
Python and Scapy were used to programmatically recalculate and validate checksums for packets in a pcap file.

## Tools Used
- Wireshark
- Python 3
- Scapy

## Notes
Some packets may show checksum validation as unverified or false due to checksum offloading performed by network interface hardware.

## Author
Muthu Venkatesh M
