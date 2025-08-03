import nmap
from openai import OpenAI
from dotenv import load_dotenv

def hosts_scan(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-sn")
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts

def services_scan(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-sV")
    network_data = {}
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            network_data[host] = {}
            for proto in nm[host].all_protocols():
                network_data[host][proto] = {}
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['product'] + " " + nm[host][proto][port]['version']
                    network_data[host][proto][port] = {'service': service, 'version': version}
    return network_data

def hosts_priority(network_data):
    load_dotenv()
    client = OpenAI()
    chat_completion = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "Eres un experto en Ciberseguridad y en gestion y priorizacion de vulnerabilidades."},
            {"role": "user", "content": f"Teniendo en cuenta el siguiente descubrimiento de hosts, puertos y servicios, ordena los hosts de más vulnerable a menos vulnerable y propon los siguientes pasos para la fase de explotación en un ejercicio de hacking etico.\n\n {network_data}"}
        ],
        model="gpt-4o-mini"
    )
    return chat_completion.choices[0].message.content

if __name__ == "__main__":
    network_data = services_scan("192.168.238.0/24")
    print(hosts_priority(network_data))
