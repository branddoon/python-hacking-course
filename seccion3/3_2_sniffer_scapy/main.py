from sniffer_scapy import SnifferScapy

if __name__ == "__main__":
    sniffer = SnifferScapy()
    sniffer.start_capture(interface="eth0")
    packets = sniffer.filter_by_text('phrack')
    sniffer.export_to_pcap(packets, "phrack_packets.pcap")