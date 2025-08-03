import socket 

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect(("localhost", 8080))

try:
    while True:
        data = input("Introduce los datos para enviar: ")
        client.sendall(data.encode())
except KeyboardInterrupt:
    client.close()