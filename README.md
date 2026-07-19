# 🍯 Honeypot — Servidor Falso para Análise de Ataques

> **Projeto Final — Segurança Computacional**  
> Simulação de serviços vulneráveis para captura e análise de tentativas de invasão.

---

## 📋 Índice

1. [Introdução e Motivação](#-introdução-e-motivação)
2. [Arquitetura do Projeto](#-arquitetura-do-projeto)
3. [Estrutura de Arquivos](#-estrutura-de-arquivos)
4. [Pré-requisitos](#-pré-requisitos)
5. [Como Executar](#-como-executar)
   - [Modo Local (sem Docker)](#modo-local-sem-docker)
   - [Modo Docker (isolado — recomendado)](#modo-docker-isolado--recomendado)
6. [Gerando Dados de Teste](#-gerando-dados-de-teste)
7. [Analisando os Logs e Gerando o Relatório](#-analisando-os-logs-e-gerando-o-relatório)
8. [Formato dos Logs](#-formato-dos-logs)
9. [Riscos, Cuidados Éticos e Legais](#️-riscos-cuidados-éticos-e-legais)
10. [Metodologia](#-metodologia)
11. [Conclusão](#-conclusão)

---

## 📖 Introdução e Motivação

Este projeto propõe a criação de um **honeypot**: um servidor falso que simula ser um serviço vulnerável — como um SSH ou FTP mal configurado — com o objetivo de **atrair tentativas de acesso indevido**.

O sistema **não expõe dados ou serviços reais**: funciona de forma totalmente isolada, apenas registrando informações sobre quem tenta se conectar, quais comandos são executados e quais credenciais são testadas.

### Por que usar um honeypot?

A abordagem é essencialmente **defensiva**, representando a estratégia de *"conhecer o inimigo"* na prática:

| Estratégia Reativa | Estratégia com Honeypot |
|---|---|
| Aguarda o ataque acontecer | Observa o atacante em ambiente controlado |
| Detecta após o dano | Coleta inteligência antes do dano |
| Responde a incidentes | Identifica padrões e previne ataques |

Ao final da execução, é gerado um **relatório com gráficos** contendo estatísticas dos acessos capturados: origem, frequência, tipo de tentativa, credenciais mais usadas e horários de pico — demonstrando como essa técnica é utilizada por equipes de segurança reais.

---

## 🏗️ Arquitetura do Projeto

```
┌─────────────────────────────────────────────────────────────┐
│                    HONEYPOT (honeypot.py)                    │
│                                                             │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│   │  SSH Falso   │  │  FTP Falso   │  │   HTTP Falso     │ │
│   │  Porta 2222  │  │  Porta 2121  │  │   Porta 8080     │ │
│   │              │  │              │  │                  │ │
│   │ • Banner SSH │  │ • Banner FTP │  │ • Resp. Apache   │ │
│   │ • Captura    │  │ • Captura    │  │ • Captura path   │ │
│   │   usuário/   │  │   usuário/   │  │   User-Agent     │ │
│   │   senha      │  │   senha      │  │   e headers      │ │
│   │ • Shell falso│  │              │  │                  │ │
│   └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
│          └─────────────────┴───────────────────┘           │
│                             │                               │
│                    logs/eventos.json                        │
│                   (um JSON por linha)                       │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              ANALISADOR (analisar_logs.py)                   │
│                                                             │
│  • Lê eventos.json                                          │
│  • Calcula estatísticas (IPs, credenciais, horários...)     │
│  • Gera gráficos PNG (matplotlib)                           │
│  • Gera relatório Markdown (relatorio/relatorio.md)         │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Estrutura de Arquivos

```
projeto-final-seguranca/
├── honeypot.py           # Servidor falso (SSH + FTP + HTTP)
├── simular_ataques.py    # Simulador de ataques para gerar dados de teste
├── analisar_logs.py      # Análise estatística + geração de gráficos e relatório
├── requirements.txt      # Dependências Python
├── Dockerfile            # Container isolado para execução segura
├── .dockerignore
├── README.md
├── logs/
│   └── eventos.json      # Log de eventos (gerado automaticamente)
└── relatorio/            # Gerado pelo analisar_logs.py
    ├── relatorio.md
    ├── 01_por_servico.png
    ├── 02_top_ips.png
    ├── 03_top_credenciais.png
    ├── 04_atividade_hora.png
    ├── 05_top_http_paths.png
    └── 06_top_comandos.png
```

---

## ✅ Pré-requisitos

### Modo Local

- Python **3.10+**
- pip / venv

```bash
# Criar e ativar o ambiente virtual (necessário em sistemas Linux modernos)
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Instalar dependências
pip install -r requirements.txt
```

> **Nota**: Após ativar o `.venv`, todos os comandos `python` e `pip` usarão o ambiente isolado. Para desativar: `deactivate`.

### Modo Docker

- [Docker](https://docs.docker.com/get-docker/) instalado e rodando

---

## 🚀 Como Executar

### Modo Local (sem Docker)

> ⚠️ **Aviso**: Certifique-se de estar em um ambiente seguro e isolado. Nunca exponha as portas do honeypot para a internet em produção sem isolamento adequado.

**Terminal 1 — Iniciar o honeypot:**

```bash
python honeypot.py
```

Saída esperada:
```
==================================================
        HONEYPOT — Servidor de Análise
==================================================
Logs salvos em: logs/eventos.json

[*] Honeypot SSH escutando em 0.0.0.0:2222
[*] Honeypot FTP escutando em 0.0.0.0:2121
[*] Honeypot HTTP escutando em 0.0.0.0:8080
```

Para encerrar: **`Ctrl+C`**

---

### Modo Docker (isolado — recomendado)

O modo Docker garante isolamento total: o honeypot roda em um container sem acesso à rede do host além das portas explicitamente mapeadas.

**Passo 1 — Construir a imagem:**

```bash
docker build -t honeypot .
```

**Passo 2 — Iniciar o container:**

```bash
docker run -d \
  --name honeypot \
  -p 2222:2222 \
  -p 2121:2121 \
  -p 8080:8080 \
  -v $(pwd)/logs:/app/logs \
  honeypot
```

| Flag | Descrição |
|---|---|
| `-d` | Roda em background |
| `-p HOST:CONTAINER` | Mapeia portas do container para o host |
| `-v $(pwd)/logs:/app/logs` | Persiste os logs fora do container |

**Verificar logs em tempo real:**

```bash
docker logs -f honeypot
```

**Parar o container:**

```bash
docker stop honeypot && docker rm honeypot
```

**Rodar o simulador de ataques dentro do container:**

```bash
docker exec honeypot python simular_ataques.py
```

**Rodar a análise dentro do container:**

```bash
docker exec honeypot python analisar_logs.py
# Copiar o relatório para o host:
docker cp honeypot:/app/relatorio ./relatorio
```

---

## 🧪 Gerando Dados de Teste

Com o honeypot já rodando (Terminal 1 ou Docker), abra outro terminal:

```bash
# Terminal 2 — simular ataques
python simular_ataques.py
```

O script simula:
- **10 tentativas SSH** com credenciais comuns (`root/root`, `admin/admin`, etc.)
- **5 tentativas FTP** com as mesmas credenciais
- **5 requisições HTTP** em paths conhecidos (`/wp-login.php`, `/.env`, `/admin`, etc.)

Saída esperada:
```
Simulando ataques contra o honeypot...

[SSH] tentativa 1: root/root
[SSH] tentativa 2: root/123456
...
[HTTP] GET /wp-login.php HTTP/1.1
...
Simulação concluída. Verifique logs/eventos.json
```

> **Dica**: Para gerar mais dados variados, execute o simulador múltiplas vezes ou edite `CREDENCIAIS` e `HTTP_PATHS` em `simular_ataques.py`.

---

## 📊 Analisando os Logs e Gerando o Relatório

Com `logs/eventos.json` populado, rode o analisador:

```bash
python analisar_logs.py
```

**Opções disponíveis:**

```bash
python analisar_logs.py --log logs/eventos.json --out relatorio/
```

| Argumento | Padrão | Descrição |
|---|---|---|
| `--log` | `logs/eventos.json` | Caminho para o arquivo de log |
| `--out` | `relatorio/` | Diretório de saída para gráficos e relatório |

**O que é gerado:**

| Arquivo | Conteúdo |
|---|---|
| `relatorio/relatorio.md` | Relatório completo em Markdown |
| `relatorio/01_por_servico.png` | Gráfico: eventos por serviço |
| `relatorio/02_top_ips.png` | Gráfico: IPs mais ativos |
| `relatorio/03_top_credenciais.png` | Gráfico: pares usuário/senha mais usados |
| `relatorio/04_atividade_hora.png` | Gráfico: atividade por hora do dia |
| `relatorio/05_top_http_paths.png` | Gráfico: paths HTTP mais acessados |
| `relatorio/06_top_comandos.png` | Gráfico: comandos SSH mais digitados |

**Resumo no terminal:**
```
============================================================
   RESUMO — ANÁLISE DO HONEYPOT
============================================================

Total de eventos capturados : 20

Por serviço:
  SSH    → 10 eventos
  FTP    →  5 eventos
  HTTP   →  5 eventos

Top 5 IPs atacantes:
  127.0.0.1            20 tentativas

Top 5 credenciais (usuário/senha):
  root/root             1×
  root/123456           1×
  ...
```

---

## 📄 Formato dos Logs

O arquivo `logs/eventos.json` usa o formato **NDJSON** (um objeto JSON por linha):

**Evento SSH:**
```json
{
  "timestamp": "2026-07-18T15:00:05.151448",
  "servico": "ssh",
  "ip": "127.0.0.1",
  "porta_origem": 60889,
  "acao": "tentativa_login",
  "usuario": "root",
  "senha": "root",
  "comandos": ["ls", "whoami"]
}
```

**Evento FTP:**
```json
{
  "timestamp": "2026-07-18T15:00:08.206730",
  "servico": "ftp",
  "ip": "127.0.0.1",
  "porta_origem": 60900,
  "acao": "tentativa_login",
  "usuario": "root",
  "senha": "root",
  "comandos": []
}
```

**Evento HTTP:**
```json
{
  "timestamp": "2026-07-18T15:00:09.712562",
  "servico": "http",
  "ip": "127.0.0.1",
  "porta_origem": 60905,
  "acao": "requisicao_http",
  "request_line": "GET /wp-login.php HTTP/1.1",
  "user_agent": "Mozilla/5.0 (scanner)",
  "host": "127.0.0.1",
  "raw_headers": {"Host": "127.0.0.1", "User-Agent": "Mozilla/5.0 (scanner)"}
}
```

**Lendo manualmente em Python:**
```python
import json

with open("logs/eventos.json") as f:
    eventos = [json.loads(linha) for linha in f if linha.strip()]

# Filtrar só SSH
ssh = [e for e in eventos if e["servico"] == "ssh"]

# Top credenciais
from collections import Counter
print(Counter((e["usuario"], e["senha"]) for e in ssh).most_common(5))
```

---

## ⚖️ Riscos, Cuidados Éticos e Legais

O uso de honeypots, mesmo em contexto acadêmico, exige atenção a questões éticas e jurídicas:

### ✅ Boas Práticas

| Cuidado | Descrição |
|---|---|
| **Isolamento total** | Nunca conecte o honeypot a sistemas de produção ou redes corporativas sem autorização. Use containers ou VMs isoladas. |
| **Não expor à internet** | Em ambiente acadêmico, mantenha o honeypot apenas na rede local (localhost ou LAN controlada). |
| **Anonimizar dados** | Ao publicar resultados, anonimize IPs reais para proteger a privacidade dos usuários. |
| **Uso defensivo** | Os dados coletados devem ser usados exclusivamente para análise, pesquisa e melhoria de segurança. |
| **Não contra-atacar** | Identificar o IP de um atacante não autoriza qualquer retaliação. Isso é ilegal. |

### ⚠️ Base Legal (Brasil)

- **Lei nº 12.737/2012 (Lei Carolina Dieckmann)**: criminaliza invasão de dispositivos informáticos.
- **LGPD (Lei nº 13.709/2018)**: regula o tratamento de dados pessoais, incluindo IPs de usuários.
- **Marco Civil da Internet (Lei nº 12.965/2014)**: define direitos e deveres no uso da internet.

> Este projeto é estritamente acadêmico. Todos os testes foram realizados em ambiente local controlado (`localhost`), sem exposição de dados reais ou invasão de sistemas de terceiros.

---

## 🔬 Metodologia

O projeto seguiu a seguinte metodologia:

```
1. PLANEJAMENTO
   └─ Divisão de tarefas, definição de serviços e formato de log

2. IMPLEMENTAÇÃO DO HONEYPOT (Pessoa 1)
   ├─ Servidor falso multi-serviço (SSH, FTP, HTTP)
   ├─ Captura estruturada em JSON
   └─ Simulador de ataques para geração de dados de teste

3. ANÁLISE E RELATÓRIO (Pessoa 2)
   ├─ Script de análise estatística dos logs
   ├─ Geração de gráficos com matplotlib
   └─ Relatório Markdown com interpretação dos dados

4. ISOLAMENTO
   └─ Containerização com Docker para execução segura

5. DOCUMENTAÇÃO
   └─ README completo com instruções de uso e contexto acadêmico
```

### Serviços Simulados

| Serviço | Porta | O que simula | O que captura |
|---|---|---|---|
| **SSH Falso** | 2222 | Banner OpenSSH 7.4 + prompt de login + shell | IP, usuário, senha, comandos digitados |
| **FTP Falso** | 2121 | Banner ProFTPD + comandos USER/PASS/QUIT | IP, usuário, senha, comandos FTP |
| **HTTP Falso** | 8080 | Resposta Apache 2.4 com página padrão | IP, path requisitado, User-Agent, headers |

---

## 📝 Conclusão

Este projeto demonstrou na prática como honeypots funcionam como ferramentas de inteligência defensiva. Os principais aprendizados foram:

1. **Ataques são automatizados**: bots testam credenciais padrão em segundos, sem intervenção humana.
2. **Padrões são previsíveis**: as mesmas senhas (`root`, `123456`, `admin`) aparecem consistentemente, evidenciando a importância de políticas de senha fortes.
3. **Reconhecimento imediato**: os primeiros comandos digitados por atacantes sempre buscam informações do sistema (`whoami`, `id`, `uname`).
4. **Varredura web é contínua**: scanners automatizados testam paths conhecidos (`/wp-login.php`, `/.env`) em busca de vulnerabilidades expostas.
5. **Isolamento é crítico**: o uso de Docker garante que o experimento seja seguro mesmo em ambiente de desenvolvimento.

O honeypot, como ferramenta de segurança, não substitui firewalls ou sistemas de detecção de intrusão, mas complementa a postura de segurança ao fornecer dados reais sobre comportamento de atacantes, permitindo que equipes de segurança antecipem e previnam ameaças com base em evidências.

---

## 👥 Divisão de Tarefas

| Responsabilidade | Integrante |
|---|---|
| Implementação do servidor honeypot (`honeypot.py`) | Pessoa 1 |
| Script simulador de ataques (`simular_ataques.py`) | Pessoa 1 |
| Script de análise e geração de relatório (`analisar_logs.py`) | Pessoa 2 |
| Containerização com Docker (`Dockerfile`) | Pessoa 2 |
| Documentação e README | Pessoa 2 |

---

*Projeto Final — Segurança Computacional*