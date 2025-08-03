from dotenv import load_dotenv
import os 
import requests
import urllib3
import time

#Desactivamos el warning de la comprobacion del certificado
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusScanner:

    def __init__(self):
        load_dotenv()
        self.base_url = os.getenv("NESSUS_URL")
        self.username = os.getenv("NESSUS_USERNAME")
        self.password = os.getenv("NESSUS_PASSWORD")
        self.token = None
    
    def create_session(self):
        response = requests.post(f"{self.base_url}/session", json={"username":self.username, "password": self.password}, verify=False)
        if response.status_code == 200:
            self.token = response.json()['token']
        else: 
            print(f"Error al crear la sesion: {response.status_code} - {response.text}")
            return False
        return True
    
    def validate_session_token(self):
        if not self.token:
            print("No hay token de sesion. Iniciando sesion...")
        if not self.create_session():
            return 
    
    def get_policies(self):
        self.validate_session_token()
        headers = {"X-Cookie": f"token={self.token}"}
        response = requests.get(f"{self.base_url}/policies", headers=headers, verify=False)
        if response.status_code == 200:
            policies = response.json()
            print("Lista de politicas:", policies)
        else:
            print(f"Error al mostrar las politicas: {response.status_code} - {response.text}")
    
    def create_scan(self, uuid, scan_name, text_targets, policy_id=None, description="", enabled=True, lauch="ON_DEMAND"):
        self.validate_session_token()
        scan_settings={
            "uuid":uuid,
            "settings":{
                "name":scan_name,
                "description": description,
                "enabled": str(enabled).lower(),
                "lauch":lauch,
                "text_targets": text_targets,
                "agent_group_id":[],
                "policy_id": policy_id
            }
        }

        headers = {"X-Cookie", f"token={self.token}"}
        response = requests.post(f"{self.base_url}/scans", json=scan_settings, headers=headers, verify=False)

        if response.status_code == 200:
            scan = response.json()
        else:
            print(f"Error al crear el escaneo en Nessus: {response.status_code} - {response.text}")

    def list_scans(self, folder_id=None, last_modification_date=None):
        self.validate_session_token()
        headers = {"X-Cookie": f"token={self.token}"}
        params = {}
        if folder_id:
            params["folder_id"] = folder_id
        if last_modification_date:
            params["last_modification_date"] = last_modification_date
        
        response = requests.get(f"{self.base_url}/scans", headers=headers, params=params, verify=False)

        if response.status_code == 200:
            scans = response.json().get("scans",[])
            if scans:
                for scan in scans:
                    print(f"ID: {scan['id']}, Nombre: {scan['name']}, Estado: {scan['status']}")
            else:
                print("No se encontraron escaneos")
            return scans
        else:
            print(f"Error al obtener el listado de escaneos: {response.status_code} - {response.text}")
            return None

    def export_scan(self, scan_id, format_type, file_id=None):
        self.validate_session_token()
        headers = {"X-Cookie": f"token={self.token}"}
        export_payload = {'format': format_type, 'template_id':36}
        export_response = requests.post(f"{self.base_url}/scans/{scan_id}/export", json=export_payload, headers=headers, verify=False)
        if export_response.status_code != 200:
            print(f"Error al exportar el escaneo: {export_response.status_code} - {export_response.text}")
            return None
        if not file_id:
            file_id = export_response.json()['file']
        polling_interval = 10
        while True:
            status_response = requests.get(f"{self.base_url}/scans/{scan_id}/export/{file_id}/status", headers=headers, verify=False)
            print(f"Consultando el estado del informe: Estado {status_response.json()['status']}")
            if status_response.status_code == 200 and status_response.json()['status'] == 'ready':
                break
            time.sleep(polling_interval)
        download_response = requests.get(f"{self.base_url}/scans/{scan_id}/export/{file_id}/download", headers=headers, verify=False)
        if download_response.status_code == 200:
            file_path = f"scan_{scan_id}_export.{format_type}"
            with open(file_path, 'wb') as f:
                f.write(download_response.content)
            print(f"Escaneo exportado y descargado con exito en: {file_path}")
        else:
            print(f"Error al descarga el escaneo exportado: {export_response.status_code} - {export_response.text}")
