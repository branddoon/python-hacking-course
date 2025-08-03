from networ_analyzer import NetworkAnalyzer

if __name__ == "__main__":
    analyzer = NetworkAnalyzer("192.168.1.64/24")
    data = analyzer.scan_devices_by_ARP()
    analyzer.pretty_print(data, data_type="hosts_arp")