from scapy.all import sniff, IP, TCP, UDP, Raw

class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback

    def process_packet(self, packet):
        if IP in packet:
            data = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "proto": packet[IP].proto,
                "payload": bytes(packet[Raw].load).decode(errors="ignore") if Raw in packet else ""
            }
            self.callback(data)

    def start_sniffing(self):
        sniff(prn=self.process_packet, store=0)
