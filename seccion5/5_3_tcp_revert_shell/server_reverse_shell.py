import socket 

server_ip = "0.0.0.0" #Escuchando conexiones en todas las interfaces disponibles
server_port = 4242

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_ip, server_port))

server_socket.listen(5) #5 conexiones maximas en cola
print(f"Escuchando conexiones en {server_ip}:{server_port}...")

#Aceptar conexion entrante
client_socket, client_address = server_socket.accept()
print(f"Conexion recibida de: {client_address}")

#Enviar y recibir comandos
try:
    while True:
        #Solicitar al usuario el comando a ejecutar
        command = input("> ") + "\n"

        #Enviar comando al cliente
        client_socket.send(command.encode())

        #Recibir y mostrar la respuesta 
        response = client_socket.recv(1024)
        print(response.decode())
except KeyboardInterrupt:
    print("Cerrando la conexion")

finally:
    client_socket.close()
    server_socket.close()
