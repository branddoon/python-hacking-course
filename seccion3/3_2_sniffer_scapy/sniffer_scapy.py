from scapy.all import sniff,wrpcap,PcapReader

class SnifferScapy:
    def __init__(self):
        self.captured_packets = []

    def start_capture(self, interface="any", filter=""):
        print("Captura de paquetes iniciada. Pulsa Ctr+C para detenerla.")
        try:
            self.captured_packets = sniff(
                iface=interface,
                filter=filter,
                prn=lambda x: x.summary(),
                store=True
            )
        except KeyboardInterrupt:
            print(f"Captura finalizada. El numero de paquetes capturados es: {len(self.captured_packets)}")
    
    def read_capture(self, pcapfile, filers=""):
        try:
            self.captured_packets = [pkt for pkt in PcapReader(pcapfile)]
            print(f"Lectura correcta del fichero: {pcapfile}")
        except Exception as e:
            print(f"Error al leer el fichero: {pcapfile}")

    def filter_by_protocol(self, protocol):
        filtered_packets= [pkt for pkt in self.captured_packets if pkt.haslayer(protocol)]
        return filtered_packets
    
    def filter_by_text(self, text):
        filtered_packets =[]
        for pkt in self.captured_packets:
            found = False
            layer = pkt
            while layer:
                for field in layer.fields_desc:
                    field_name = field.name
                    field_value = layer.getfieldval(field_name)
                    if text in field_name or text in str(field_value):
                        filtered_packets.append(pkt)
                        found = True
                        break
                if found:
                    break
                layer = layer.payload
        return filtered_packets
    
    def print_packet_details(self, packets=None):
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            packet.show()
            print("---"*20)
    
    def export_to_pcap(self, packets, filename="capture.pcap"):
        wrpcap(filename,packets)
        print("Paquetes guardados en disco satisfactoriamente.")
