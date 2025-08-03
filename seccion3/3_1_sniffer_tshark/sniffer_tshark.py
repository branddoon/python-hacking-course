import pyshark
from scapy.all import wrpcap, Ether

class SnifferTshark:

    def __init__(self):
        self.capture = None
        self.captured_packets = []
    
    def start_capture(self, interface="any", display_filter=""):
        self.capture = pyshark.LiveCapture(
            interface = interface,
            display_filter = display_filter,
            use_json = True, 
            include_raw = True
        )

        try:
            print("[+] Captura de paquetes iniciada. Pulsa Crtl+C para detenerla")
            for packet in self.capture.sniff_continuously():
                self.captured_packets.append(packet)
        except (KeyboardInterrupt, EOFError):
            print(f"[+] Captura finalizada. Paquetes capturados {len(self.captured_packets)}")
    
    def read_capture(self, pcapfile, display_filter=""):
        try:
            self.capture = pyshark.FileCapture(
                input_file=pcapfile,
                display_filter=display_filter,
                keep_packets=False,
                ##use_json=True,
                ##include_raw=True
            )
            self.captured_packets = [pkt for pkt in self.capture]
            print(f'Lectura de {pcapfile} terminada')
        except Exception as e:
            print(f'Error al leer el fichero {pcapfile}')

    def filter_by_protocol(self, protocol):
        filtered_packets = [pkt for pkt in self.captured_packets if protocol in pkt]
        return filtered_packets
    
    def filter_by_text(self, text):
        filtered_packets = []
        for pkt in self.captured_packets:
            for layer in pkt.layers:
                for field_line in layer._get_all_field_lines():
                    if text in field_line:
                        filtered_packets.append(pkt)
                        break
        return filtered_packets

    def export_to_pcap(self, packets, filename='capture.pcap'):
        scapy_packets = [Ether((pkt.get_raw_packet())) for pkt in packets]
        wrpcap(filename, scapy_packets)
        print(f"[+] Paquetes guardados en {filename}")

    def print_packet_detail(self, packets=None):
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            print(packet)
            print("---"*20)
        
