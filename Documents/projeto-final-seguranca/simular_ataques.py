"""
Simula ataques contra o honeypot para gerar dados
"""

import socket
import time
import random

HOST = "127.0.0.1"

# Credenciais mais tentadas por atacantes

CREDENCIAIS = [
    ("root", "root"), ("root", "123456"), ("admin", "admin"),
    ("admin", "password"), ("user", "user"), ("pi", "raspberry"),
    ("oracle", "oracle"), ("test", "test"), ("guest", "guest"),
    ("ubuntu", "ubuntu"),
]

COMANDOS_SSH = ["ls", "whoami", "cat /etc/passwd", "uname -a", "id"]

# PATHS comuns dos servidores 

HTTP_PATHS = [
    "GET / HTTP/1.1", "GET /admin HTTP/1.1", "GET /wp-login.php HTTP/1.1",
    "GET /.env HTTP/1.1", "GET /phpmyadmin HTTP/1.1",
]

# Conecta com o SSH como atacante
# Recebendo banner e enviando login e senha e algum comando 

def simular_ssh(usuario: str, senha: str):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((HOST, 2222))
        s.recv(1024)                         
        s.recv(1024)                          
        s.sendall(f"{usuario}\n".encode())
        s.recv(1024)                          
        s.sendall(f"{senha}\n".encode())
        s.recv(1024)                          
        s.recv(1024)                          

        if random.random() > 0.5:           
            cmd = random.choice(COMANDOS_SSH)
            s.sendall(f"{cmd}\n".encode())
            s.recv(1024)

        s.close()
    except Exception:
        pass

# Conecta com o FTP como atacante

def simular_ftp(usuario: str, senha: str):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((HOST, 2121))
        s.recv(1024)                          
        s.sendall(f"USER {usuario}\r\n".encode())
        s.recv(1024)
        s.sendall(f"PASS {senha}\r\n".encode())
        s.recv(1024)
        s.sendall(b"QUIT\r\n")
        s.recv(1024)
        s.close()
    except Exception:
        pass

# Conecta com o HTTP como atacante

def simular_http(path: str):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((HOST, 8080))
        req = (
            f"{path}\r\n"
            f"Host: {HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (scanner)\r\n"
            f"\r\n"
        )
        s.sendall(req.encode())
        s.recv(4096)
        s.close()
    except Exception:
        pass


if __name__ == "__main__":
    print("Simulando ataques contra o honeypot...\n")

    for i, (u, p) in enumerate(CREDENCIAIS):
        print(f"[SSH] tentativa {i+1}: {u}/{p}")
        simular_ssh(u, p)
        time.sleep(0.3)

    for i, (u, p) in enumerate(CREDENCIAIS[:5]):
        print(f"[FTP] tentativa {i+1}: {u}/{p}")
        simular_ftp(u, p)
        time.sleep(0.3)

    for path in HTTP_PATHS:
        print(f"[HTTP] {path}")
        simular_http(path)
        time.sleep(0.2)

    print("\nSimulação concluída. Verifique logs/eventos.json")
