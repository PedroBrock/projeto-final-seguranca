import socket
import threading
import json
import os
from datetime import datetime

LOG_FILE = "logs/eventos.json"
HOST = "0.0.0.0"

SERVICES = {
    "ssh":  {"port": 2222, "banner": "SSH-2.0-OpenSSH_7.4\r\n"},
    "ftp":  {"port": 2121, "banner": "220 ProFTPD 1.3.5 Server (ProFTPD) [127.0.0.1]\r\n"},
    "http": {"port": 8080, "banner": ""},
}

HTTP_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache/2.4.41 (Ubuntu)\r\n"
    "Content-Type: text/html\r\n\r\n"
    "<html><body><h1>It works!</h1></body></html>"
)

os.makedirs("logs", exist_ok=True)

# Guardar informações da conexão no log

def salvar_evento(evento: dict):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")
    print(f"[{evento['timestamp']}] [{evento['servico'].upper()}] "
          f"{evento['ip']}:{evento['porta_origem']} — {evento.get('acao', '')}")

# Formato do log

def base_evento(servico: str, conn: socket.socket, addr: tuple) -> dict:
    return {
        "timestamp":     datetime.now().isoformat(),
        "servico":       servico,
        "ip":            addr[0],
        "porta_origem":  addr[1],
    }


# Simula o SSH, capturando usuário e senha
# E depois simulando um shell

def handle_ssh(conn: socket.socket, addr: tuple):
    evento = base_evento("ssh", conn, addr)
    usuario = ""
    senha   = ""
    comandos = []

    try:
        conn.sendall(SERVICES["ssh"]["banner"].encode())

        conn.sendall(b"login: ")
        usuario = conn.recv(256).decode(errors="ignore").strip()

        conn.sendall(b"Password: ")
        senha = conn.recv(256).decode(errors="ignore").strip()

        conn.sendall(b"\nAccess denied\n\n")

        # Shell Falso
        conn.sendall(b"$ ")
        while True:
            dado = conn.recv(512)
            if not dado:
                break
            cmd = dado.decode(errors="ignore").strip()
            if cmd:
                comandos.append(cmd)
                conn.sendall(b"command not found\n$ ")

    except Exception:
        pass
    finally:
        evento.update({
            "acao":      "tentativa_login",
            "usuario":   usuario,
            "senha":     senha,
            "comandos":  comandos,
        })
        salvar_evento(evento)
        conn.close()

# Simula o FTP, lendo o texto linha por linha

def handle_ftp(conn: socket.socket, addr: tuple):
    evento = base_evento("ftp", conn, addr)
    usuario = ""
    senha   = ""
    comandos = []

    try:
        conn.sendall(SERVICES["ftp"]["banner"].encode())

        while True:
            dado = conn.recv(512)
            if not dado:
                break
            linha = dado.decode(errors="ignore").strip()
            if not linha:
                continue

            partes = linha.split(" ", 1)
            cmd    = partes[0].upper()
            arg    = partes[1] if len(partes) > 1 else ""

            if cmd == "USER":
                usuario = arg
                conn.sendall(b"331 Password required\r\n")
            elif cmd == "PASS":
                senha = arg
                conn.sendall(b"530 Login incorrect\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye\r\n")
                break
            else:
                comandos.append(linha)
                conn.sendall(b"500 Unknown command\r\n")

    except Exception:
        pass
    finally:
        evento.update({
            "acao":     "tentativa_login",
            "usuario":  usuario,
            "senha":    senha,
            "comandos": comandos,
        })
        salvar_evento(evento)
        conn.close()

# Simula um HTTP, lendo a requisição e extraindo as informações

def handle_http(conn: socket.socket, addr: tuple):
    evento = base_evento("http", conn, addr)

    try:
        dado = conn.recv(4096).decode(errors="ignore")
        linhas = dado.split("\r\n")
        primeira_linha = linhas[0] if linhas else ""

        headers = {}
        for linha in linhas[1:]:
            if ": " in linha:
                chave, valor = linha.split(": ", 1)
                headers[chave] = valor

        conn.sendall(HTTP_RESPONSE.encode())

        evento.update({
            "acao":          "requisicao_http",
            "request_line":  primeira_linha,
            "user_agent":    headers.get("User-Agent", ""),
            "host":          headers.get("Host", ""),
            "raw_headers":   headers,
        })

    except Exception:
        evento.update({"acao": "conexao_http", "erro": "falha ao ler requisicao"})
    finally:
        salvar_evento(evento)
        conn.close()


HANDLERS = {
    "ssh":  handle_ssh,
    "ftp":  handle_ftp,
    "http": handle_http,
}

# Fica esperando conexões, e cria uma thread para cada conexão

def iniciar_servidor(servico: str, host: str, port: int):
    handler = HANDLERS[servico]
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, port))
    servidor.listen(50)
    print(f"[*] Honeypot {servico.upper()} escutando em {host}:{port}")

    while True:
        try:
            conn, addr = servidor.accept()
            t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[ERRO] {servico}: {e}")


if __name__ == "__main__":
    print("=" * 50)
    print("        HONEYPOT — Servidor de Análise")
    print("=" * 50)
    print(f"Logs salvos em: {LOG_FILE}\n")

    threads = []
    for nome, cfg in SERVICES.items():
        t = threading.Thread(
            target=iniciar_servidor,
            args=(nome, HOST, cfg["port"]),
            daemon=True,
        )
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Honeypot encerrado.")
