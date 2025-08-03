import socket 

#Creamos un servidor TCP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Asignamos el socket a una direccion local y a un puerto
server.bind(("localhost",8080))

#Empieza a escuchar conexiones 
server.listen()

#Acepta una conexion
conexion, address = server.accept()

with conexion:
    print("Conectado a: ", address)
    while True:
        data = conexion.recv(1024)
        if not data:
            break
        print("Datos recibidados del cliente: ", data.decode())

conexion.close()


