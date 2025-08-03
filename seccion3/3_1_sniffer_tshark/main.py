from sniffer_tshark import SnifferTshark

if __name__ == "__main__":
    sniffer = SnifferTshark()
    sniffer.read_capture("/home/kali/Documents/python-hacking/seccion3/3_1_sniffer_tshark/caputure_wireshark.pcapng")
    ##sniffer.start_capture()
    packets = sniffer.filter_by_text("phrack")
    sniffer.print_packet_detail(packets)
    ##sniffer.export_to_pcap(packets)

