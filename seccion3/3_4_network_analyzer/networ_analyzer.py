import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from scapy.all import *
import logging
from smb.SMBConnection import SMBConnection

#Desactivamos la salida de warnings para Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkAnalyzer:
    def __init__(self, network_range, timeout=1):
        self.network_range = network_range
        self.timeout = timeout

    def scan_host_sockets(self, ip, port=1000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (port, True)
        except (socket.timeout, socket.error):
            return (port, False)
    
    def scan_host_scapy(self, ip, scan_ports=(135,445,139)):
        for port in scan_ports:
            packet = IP(dst=ip)/TCP(dport=port, flags='S', window=0x4001, options=[('MSS', 1460)])
            response, _ = sr(packet, timeout=self.timeout, verbose=0)
            if response:
                return (ip, True)
        return (ip, False)
    
    def hosts_scan_arp(self):
        hosts_up = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        response, _ = tqdm(srp(arp_request, timeout=self.timeout, iface_hint=str(network[1]), verbose=0), desc="Escaneando con ARP")
        for _, received in response:
            hosts_up.append(received.psrc)
        return hosts_up

    def host_scan(self, scan_ports=(135,445,139)):
        network = ipaddress.ip_network(self.network_range, strict=False)
        host_up =[]
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_host_scapy, str(host), scan_ports): host for host in tqdm(network.hosts(),desc="Escaneando hosts")}
            for future in tqdm(futures, desc="Obteniendo resultados"):
                if future.result()[1]:
                    host_up.append(future.result()[0])
        return host_up

    def ports_scan(self, port_range=(0,1000)):
        active_hosts = self.host_scan()
        all_open_ports = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            for ip in active_hosts:
                futures = []
                for port in tqdm(range(*port_range), desc=f"Escaneando puertos en {ip}"):
                    future = executor.submit(self.scan_host_sockets, ip, port)
                    futures.append(future)
                open_ports = [future.result()[0] for future in futures if future.result()[1]]
                if open_ports:
                    all_open_ports[ip] = open_ports
        return all_open_ports
    
    def get_banner(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip,port))
                s.send(b'Hello\r\n')
                return s.recv(1024).decode().strip()
        except Exception as e:
            return str(e)
        
    def services_scan(self, port_range=(0,10000)):
        active_hosts = self.host_scan()
        service_info = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            for ip in active_hosts:
                futures = []
                service_info[ip] = {}
                for port in tqdm(range(*port_range), desc=f"Obteniendo banners en {ip}"):
                    future = executor.submit(self.get_banner, ip, port)
                    futures.append((future, port))
                for future, port in futures:
                    result = future.result()
                    if result and 'timed out' not in result and 'refused' not in result and 'No route to host' not in result:
                        service_info[ip][port] = result
        return service_info

    def discover_public_smb(self, ip):
        user_name = ""
        password = ""
        local_machine_name = "laptop"
        server_machine_name = ip
        share_details = {}
        try:
            conn = SMBConnection(user_name, password, local_machine_name, server_machine_name, use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(ip, 445, timeout=self.timeout):
                print(f"Conectado a {ip}")
                for share in conn.listShares(timeout=60):
                    if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                        try:
                            files = conn.listPath(share.name, '/')
                            print('FILES')
                            print(files)
                            share_details[share.name] = [file.filename for file in files if file.filename not in ['.','..']]
                        except Exception as e:
                            print(f"No se ha podido acceder a {share.name} en {ip}: {e}")
                conn.close()
        except Exception as e:
            print(f"No se han podido obtener los recursos de {ip}: {e}")
        return ip, share_details
    
    def scan_shares(self):
        active_host = self.host_scan()
        all_shares = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.discover_public_smb, ip): ip for ip in tqdm(active_host, desc="Descubriendo recursos compartidos")}
            for future in tqdm(futures, desc="Obteniendo recursos compartidos"):
                ip, shares = future.result()
                if shares:
                    all_shares[ip] = shares
        return all_shares
    
    def scan_devices_by_ARP(self):
        print("Starting ARP scanning")
        packet = Ether(dst = "ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network_range)
        result = srp(packet, self.timeout, verbose=0)[0]
        devices = []
        for sent, received in tqdm (result, desc="Processing devices by ARP..."):
            devices.append({'ip':received.psrc, 'mac':received.hwsrc})
        print("Finished ARP scanning")
        return devices

    def pretty_print(self, data, data_type="hosts"):
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        if data_type == "hosts":
            table.add_column("Hosts up", style="bold green")
            for host in data:
                table.add_row(host, end_section=True)
        elif data_type == "ports":
            table.add_column("IP Address", style="bold green")
            table.add_column("Open ports", style="bold blue")
            for ip, ports in data.items():
                ports_str = ", ".join(map(str,ports))
                table.add_row(ip, ports_str, end_section=True)
        elif data_type == "services":
            table.add_column("IP Address", style="bold green")
            table.add_column("Port", style="bold blue")
            table.add_column("Service", style="bold yellow")
            for ip, services in data.items():
                for port, service in services.items():
                    table.add_row(ip, str(port), service, end_section=True)
        elif data_type == "shares":
            for ip, shares in data.items():
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("IP Address", style="bold green")
                table.add_column("Shared Folder", style="bold blue")
                table.add_column("Files", style="bold yellow")
                for share, files in shares.items():
                    files_str = " ,".join(files)
                    table.add_row(ip, share, files_str, end_section=True)
        elif data_type == "hosts_arp":
            table.add_column("IP Address", style="bold green")
            table.add_column("MAC", style="bold blue")
            for element in data:
                table.add_row(element['ip'], element['mac'])
        console.print(table)