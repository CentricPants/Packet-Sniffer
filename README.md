```
Packet Sniffer – Kali Linux GUI Tool
------------------------------------

This is a simple GUI-based Packet Sniffer built with Python, Tkinter, and Scapy.  
It allows users to select a network interface, filter packets by protocol (ARP, DNS, TCP, UDP, Wireless),  
and view captured packet summaries in real time.

This was a personal learning project created from scratch — a beginner-friendly tool for network analysis.

------------------------------------
Features
------------------------------------

- GUI interface using Tkinter
- Real-time packet sniffing
- Protocol filtering (ARP, DNS, TCP, UDP, Wireless Management)
- Displays Ethernet, IP, and transport-layer headers
- Captures wireless management frames (Beacon, Probe Requests)
- Logs output to 'packet_log.txt'
- Designed for Kali Linux (or any OS with root access)

------------------------------------
How to Run
------------------------------------

1. Install Python 3
2. Install dependencies:
   pip install scapy
3. Run with root privileges:
   sudo python3 packet_sniffer_gui.py
4. Select a network interface from the dropdown
5. Choose an optional protocol filter
6. Click 'Start Sniffing' to begin, 'Stop Sniffing' to stop

------------------------------------
Requirements
------------------------------------

- Python 3.x
- Scapy
- Root privileges
- Linux OS (tested on Kali Linux)

------------------------------------
File Structure
------------------------------------

packet_sniffer_gui.py     # Main GUI script  
packet_log.txt            # Log file generated during sniffing

------------------------------------
Important Notes
------------------------------------

- This tool is for educational use only.
- Use it only on networks you are authorized to monitor.
- Wireless packet capture depends on adapter compatibility (monitor mode support).
- No packet decryption is performed.

------------------------------------
Acknowledgement
------------------------------------

Built as a hands-on project to understand network traffic and packet-level analysis.

```
