# Network IDS / IPS System (Modbus + SSH Monitoring)

This project implements a simple Intrusion Detection & Prevention System (IDS/IPS) for industrial network traffic.

## 🔍 Features

- PCAP file analysis (manual & automated)
- Live traffic sniffing using Scapy
- Detection of suspicious Modbus function codes
- Detection of unauthorized IP addresses
- Basic DDoS detection (rate limiting)
- Automatic IP blocking using iptables
- Logging of detected attacks
- Export of suspicious packets to PCAP

## ⚙️ Tech Stack

- Python 3.11
- Scapy
- Docker / Docker Compose
- Linux networking (iptables, tcpdump)

## 🐳 Run with Docker

```bash
docker-compose up --build
