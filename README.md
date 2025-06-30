# Packet Sniffer – Kali Linux GUI Tool

This is a GUI-based Packet Sniffer built using **Python**, **Tkinter**, and **Scapy**.  
It allows real-time network traffic capture, supports protocol filtering, and logs the captured data for analysis.

This was developed as a personal project to explore how packet sniffing works and to gain hands-on experience with low-level networking.

---

## Features

- Simple GUI using Tkinter
- Real-time packet sniffing
- Protocol filtering:
  - ARP
  - DNS
  - TCP
  - UDP
  - Wireless Management Frames (Beacon, Probe Requests)
- Captures and logs:
  - Ethernet headers
  - IP headers
  - Transport layer ports
  - Wireless broadcast and probe frames
- Saves captured packet summaries to a `packet_log.txt` file

---

## How to Run

1. Ensure you have Python 3 installed
2. Install required dependencies:
   ```bash
   pip install scapy

Run the script with root privileges:
   ```bash
   sudo python3 Packet_Sniffer.py
