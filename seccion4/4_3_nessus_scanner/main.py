from nessus_scanner import NessusScanner

if __name__ == "__main__":
    nscanner = NessusScanner()
    nscanner.export_scan(5, "pdf")