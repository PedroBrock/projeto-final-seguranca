# 🍯 Honeypot — Servidor Falso para Análise de Ataques

> Projeto acadêmico de Segurança Computacional

---

## Estrutura do projeto

```
honeypot/
├── honeypot.py          
├── simular_ataques.py   
├── requirements.txt
├── README.md
└── logs/
    └── eventos.json     # gerado automaticamente
```

---

## Como executar

```bash
# Terminal 1 — inicia o honeypot
python honeypot.py

# Terminal 2 — simula ataques para gerar dados (opcional)
python simular_ataques.py
```

---

## Serviços simulados

| Serviço | Porta | O que captura |
|---|---|---|
| SSH falso | 2222 | IP, usuário, senha, comandos digitados |
| FTP falso | 2121 | IP, usuário, senha, comandos FTP |
| HTTP falso | 8080 | IP, path requisitado, User-Agent, headers |

---

## Formato dos logs (eventos.json)

Cada linha é um evento JSON independente:

```json
{"timestamp": "2025-05-20T14:32:10.123", "servico": "ssh", "ip": "127.0.0.1", "porta_origem": 54321, "acao": "tentativa_login", "usuario": "root", "senha": "123456", "comandos": ["ls", "whoami"]}
{"timestamp": "2025-05-20T14:32:11.456", "servico": "ftp", "ip": "127.0.0.1", "porta_origem": 54322, "acao": "tentativa_login", "usuario": "admin", "senha": "admin", "comandos": []}
{"timestamp": "2025-05-20T14:32:12.789", "servico": "http", "ip": "127.0.0.1", "porta_origem": 54323, "acao": "requisicao_http", "request_line": "GET /wp-login.php HTTP/1.1", "user_agent": "Mozilla/5.0", "host": "127.0.0.1", "raw_headers": {}}
```

---

## Para ler os logs

```python
import json

eventos = []
with open("logs/eventos.json") as f:
    for linha in f:
        eventos.append(json.loads(linha))

# Filtra só tentativas SSH
ssh = [e for e in eventos if e["servico"] == "ssh"]

# Credenciais mais tentadas
from collections import Counter
credenciais = Counter(
    (e["usuario"], e["senha"]) for e in ssh
)
print(credenciais.most_common(10))
```