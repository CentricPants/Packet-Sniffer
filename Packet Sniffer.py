import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, get_if_list, Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Dot11, Dot11Beacon, Dot11ProbeReq
import threading
import datetime

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(" Packet Sniffer - Kali Linux")
        self.root.geometry("1000x600")
        self.sniffing = False
        self.thread = None
        self.filter_protocol = tk.StringVar(value="All")

        # Interface selection
        tk.Label(root, text="Select Interface:").pack()
        self.interface_combo = ttk.Combobox(root, values=get_if_list(), width=50)
        self.interface_combo.pack(pady=5)

        # Protocol filter
        tk.Label(root, text="Filter by Protocol:").pack()
        self.protocol_filter = ttk.Combobox(root, textvariable=self.filter_protocol, values=["All", "ARP", "DNS", "TCP", "UDP", "WirelessMgmt"], width=50)
        self.protocol_filter.pack(pady=5)

        # Start and Stop buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Output display
        self.packet_display = scrolledtext.ScrolledText(root, width=120, height=25)
        self.packet_display.pack(pady=10)

        # Log file
        self.log_file = open("packet_log.txt", "w")

    def log_packet(self, text):
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S] ")
        self.packet_display.insert(tk.END, timestamp + text + '\n')
        self.packet_display.see(tk.END)
        self.log_file.write(timestamp + text + '\n')

    def process_packet(self, packet):
        proto = self.filter_protocol.get()

        # Filter by type
        if proto == "ARP" and not packet.haslayer(ARP): return
        if proto == "DNS" and not packet.haslayer(DNS): return
        if proto == "TCP" and not packet.haslayer(TCP): return
        if proto == "UDP" and not packet.haslayer(UDP): return
        if proto == "WirelessMgmt" and not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeReq)): return

        summary = ""

        if packet.haslayer(Ether):
            eth = packet[Ether]
            summary += f"[Ether] {eth.src} → {eth.dst} | "

        if packet.haslayer(IP):
            ip = packet[IP]
            summary += f"[IP] {ip.src} → {ip.dst} | Proto: {ip.proto} | "

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            summary += f"[TCP] {tcp.sport} → {tcp.dport} | "

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            summary += f"[UDP] {udp.sport} → {udp.dport} | "

        if packet.haslayer(ARP):
            arp = packet[ARP]
            summary += f"[ARP] {arp.psrc} is asking about {arp.pdst} | "

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            summary += f"[DNS] Query: {packet[DNSQR].qname.decode()} | "

        if packet.haslayer(Dot11Beacon):
            summary += f"[Wireless] Beacon from {packet[Dot11].addr2} | "
        if packet.haslayer(Dot11ProbeReq):
            summary += f"[Wireless] Probe Request from {packet[Dot11].addr2} | "

        summary += "-" * 50
        self.log_packet(summary)

    def sniff_packets(self):
        iface = self.interface_combo.get()
        sniff(iface=iface, prn=self.process_packet, stop_filter=lambda x: not self.sniffing, store=False)

    def start_sniffing(self):
        if not self.interface_combo.get():
            self.log_packet(" Please select a valid interface.")
            return
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_display.delete(1.0, tk.END)
        self.thread = threading.Thread(target=self.sniff_packets)
        self.thread.start()
        self.log_packet(" Sniffing started...")

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_packet(" Sniffing stopped.")
        self.log_file.close()

# Main
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
