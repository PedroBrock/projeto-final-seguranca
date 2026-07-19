"""
analisar_logs.py — Análise e Relatório do Honeypot
====================================================
Lê os eventos capturados pelo honeypot (logs/eventos.json),
calcula estatísticas e gera gráficos em PNG além de um
relatório textual em Markdown (relatorio.md).

Uso:
    python analisar_logs.py
    python analisar_logs.py --log logs/eventos.json --out relatorio/
"""

import json
import os
import argparse
from datetime import datetime
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")          # backend sem janela (funciona em servidor/Docker)
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


# ──────────────────────────────────────────────────────────────────────────────
# Configurações padrão
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_LOG = "logs/eventos.json"
DEFAULT_OUT = "relatorio"

PALETTE = {
    "ssh":  "#4C9BE8",
    "ftp":  "#F4A03A",
    "http": "#6BCB77",
}
PALETTE_LIST = list(PALETTE.values())


# ──────────────────────────────────────────────────────────────────────────────
# Carregamento de dados
# ──────────────────────────────────────────────────────────────────────────────

def carregar_eventos(caminho: str) -> list[dict]:
    """Lê o arquivo NDJSON linha a linha e retorna lista de eventos."""
    eventos = []
    if not os.path.exists(caminho):
        print(f"[ERRO] Arquivo de log não encontrado: {caminho}")
        return eventos
    with open(caminho, encoding="utf-8") as f:
        for i, linha in enumerate(f, 1):
            linha = linha.strip()
            if not linha:
                continue
            try:
                eventos.append(json.loads(linha))
            except json.JSONDecodeError as e:
                print(f"[AVISO] Linha {i} inválida ({e}); ignorada.")
    return eventos


# ──────────────────────────────────────────────────────────────────────────────
# Estatísticas
# ──────────────────────────────────────────────────────────────────────────────

def calcular_estatisticas(eventos: list[dict]) -> dict:
    """Retorna dicionário com todas as métricas calculadas."""
    stats = {}

    # ── totais por serviço ──
    stats["total"] = len(eventos)
    contagem_servico = Counter(e["servico"] for e in eventos)
    stats["por_servico"] = dict(contagem_servico)

    # ── IPs mais frequentes ──
    stats["top_ips"] = Counter(e["ip"] for e in eventos).most_common(10)

    # ── credenciais (somente SSH e FTP) ──
    login_eventos = [
        e for e in eventos
        if e.get("acao") == "tentativa_login" and e.get("usuario")
    ]
    stats["top_usuarios"] = Counter(
        e["usuario"] for e in login_eventos
    ).most_common(10)

    stats["top_senhas"] = Counter(
        e["senha"] for e in login_eventos if e.get("senha")
    ).most_common(10)

    stats["top_pares"] = Counter(
        (e["usuario"], e["senha"])
        for e in login_eventos if e.get("senha")
    ).most_common(10)

    # ── comandos SSH digitados ──
    todos_cmds = []
    for e in eventos:
        todos_cmds.extend(e.get("comandos", []))
    stats["top_comandos"] = Counter(todos_cmds).most_common(10)

    # ── paths HTTP requisitados ──
    http_paths = [
        e.get("request_line", "") for e in eventos if e.get("servico") == "http"
    ]
    stats["top_http_paths"] = Counter(http_paths).most_common(10)

    # ── atividade por hora do dia ──
    atividade_hora = defaultdict(int)
    for e in eventos:
        try:
            hora = datetime.fromisoformat(e["timestamp"]).hour
            atividade_hora[hora] += 1
        except (KeyError, ValueError):
            pass
    stats["atividade_hora"] = dict(atividade_hora)

    # ── atividade por dia ──
    atividade_dia = defaultdict(int)
    for e in eventos:
        try:
            dia = datetime.fromisoformat(e["timestamp"]).strftime("%Y-%m-%d")
            atividade_dia[dia] += 1
        except (KeyError, ValueError):
            pass
    stats["atividade_dia"] = dict(sorted(atividade_dia.items()))

    return stats


# ──────────────────────────────────────────────────────────────────────────────
# Geração de gráficos
# ──────────────────────────────────────────────────────────────────────────────

def _salvar(fig, caminho: str):
    fig.tight_layout()
    fig.savefig(caminho, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [gráfico] {caminho}")


def grafico_por_servico(stats: dict, out_dir: str) -> str:
    servicos = list(stats["por_servico"].keys())
    valores  = list(stats["por_servico"].values())
    cores    = [PALETTE.get(s, "#999") for s in servicos]

    fig, ax = plt.subplots(figsize=(6, 4))
    barras = ax.bar(servicos, valores, color=cores, edgecolor="white", linewidth=0.8)
    ax.bar_label(barras, padding=4, fontsize=10, fontweight="bold")
    ax.set_title("Tentativas por Serviço", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel("Nº de eventos")
    ax.set_ylim(0, max(valores) * 1.2 if valores else 1)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.spines[["top", "right"]].set_visible(False)

    caminho = os.path.join(out_dir, "01_por_servico.png")
    _salvar(fig, caminho)
    return caminho


def grafico_top_ips(stats: dict, out_dir: str) -> str:
    dados = stats["top_ips"]
    if not dados:
        return ""
    ips, contagens = zip(*dados)

    fig, ax = plt.subplots(figsize=(8, max(3, len(ips) * 0.5)))
    barras = ax.barh(list(reversed(ips)), list(reversed(contagens)),
                     color="#4C9BE8", edgecolor="white")
    ax.bar_label(barras, padding=4, fontsize=9)
    ax.set_title("Top IPs Atacantes", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Nº de tentativas")
    ax.spines[["top", "right"]].set_visible(False)

    caminho = os.path.join(out_dir, "02_top_ips.png")
    _salvar(fig, caminho)
    return caminho


def grafico_top_credenciais(stats: dict, out_dir: str) -> str:
    dados = stats["top_pares"]
    if not dados:
        return ""
    rotulos  = [f"{u}/{p}" for u, p in [d[0] for d in dados]]
    contagens = [d[1] for d in dados]

    fig, ax = plt.subplots(figsize=(9, max(3, len(rotulos) * 0.55)))
    barras = ax.barh(list(reversed(rotulos)), list(reversed(contagens)),
                     color="#F4A03A", edgecolor="white")
    ax.bar_label(barras, padding=4, fontsize=9)
    ax.set_title("Credenciais Mais Testadas (usuário/senha)", fontsize=13,
                 fontweight="bold", pad=12)
    ax.set_xlabel("Nº de tentativas")
    ax.spines[["top", "right"]].set_visible(False)

    caminho = os.path.join(out_dir, "03_top_credenciais.png")
    _salvar(fig, caminho)
    return caminho


def grafico_atividade_hora(stats: dict, out_dir: str) -> str:
    horas = list(range(24))
    valores = [stats["atividade_hora"].get(h, 0) for h in horas]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.fill_between(horas, valores, alpha=0.25, color="#6BCB77")
    ax.plot(horas, valores, marker="o", color="#6BCB77", linewidth=2,
            markersize=5)
    ax.set_title("Atividade por Hora do Dia", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Hora")
    ax.set_ylabel("Nº de eventos")
    ax.set_xticks(horas)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.spines[["top", "right"]].set_visible(False)

    caminho = os.path.join(out_dir, "04_atividade_hora.png")
    _salvar(fig, caminho)
    return caminho


def grafico_top_http_paths(stats: dict, out_dir: str) -> str:
    dados = stats["top_http_paths"]
    if not dados:
        return ""
    rotulos   = [d[0] for d in dados]
    contagens = [d[1] for d in dados]

    fig, ax = plt.subplots(figsize=(9, max(3, len(rotulos) * 0.55)))
    barras = ax.barh(list(reversed(rotulos)), list(reversed(contagens)),
                     color="#A78BFA", edgecolor="white")
    ax.bar_label(barras, padding=4, fontsize=9)
    ax.set_title("Paths HTTP Mais Requisitados", fontsize=13, fontweight="bold",
                 pad=12)
    ax.set_xlabel("Nº de requisições")
    ax.spines[["top", "right"]].set_visible(False)

    caminho = os.path.join(out_dir, "05_top_http_paths.png")
    _salvar(fig, caminho)
    return caminho


def grafico_top_comandos(stats: dict, out_dir: str) -> str:
    dados = stats["top_comandos"]
    if not dados:
        return ""
    cmds, contagens = zip(*dados)

    fig, ax = plt.subplots(figsize=(8, max(3, len(cmds) * 0.5)))
    barras = ax.barh(list(reversed(cmds)), list(reversed(contagens)),
                     color="#F87171", edgecolor="white")
    ax.bar_label(barras, padding=4, fontsize=9)
    ax.set_title("Comandos SSH Mais Digitados", fontsize=13, fontweight="bold",
                 pad=12)
    ax.set_xlabel("Nº de ocorrências")
    ax.spines[["top", "right"]].set_visible(False)

    caminho = os.path.join(out_dir, "06_top_comandos.png")
    _salvar(fig, caminho)
    return caminho


def gerar_graficos(stats: dict, out_dir: str) -> list[str]:
    """Gera todos os gráficos e retorna lista de caminhos criados."""
    os.makedirs(out_dir, exist_ok=True)
    gerados = []
    funcs = [
        grafico_por_servico,
        grafico_top_ips,
        grafico_top_credenciais,
        grafico_atividade_hora,
        grafico_top_http_paths,
        grafico_top_comandos,
    ]
    for fn in funcs:
        caminho = fn(stats, out_dir)
        if caminho:
            gerados.append(caminho)
    return gerados


# ──────────────────────────────────────────────────────────────────────────────
# Relatório Markdown
# ──────────────────────────────────────────────────────────────────────────────

def _tabela(cabecalhos: list[str], linhas: list[tuple]) -> str:
    """Formata uma tabela Markdown simples."""
    sep = " | "
    header = sep.join(cabecalhos)
    divisor = sep.join(["---"] * len(cabecalhos))
    rows = "\n".join(sep.join(str(c) for c in linha) for linha in linhas)
    return f"| {header} |\n| {divisor} |\n" + "\n".join(
        f"| {sep.join(str(c) for c in r)} |" for r in linhas
    )


def gerar_relatorio_md(stats: dict, graficos: list[str], out_dir: str,
                        log_path: str) -> str:
    agora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    caminho = os.path.join(out_dir, "relatorio.md")

    linhas = []

    # Cabeçalho
    linhas += [
        "# 🍯 Relatório de Análise — Honeypot",
        "",
        f"> Gerado em: **{agora}**  ",
        f"> Arquivo de log analisado: `{log_path}`",
        "",
        "---",
        "",
    ]

    # Sumário geral
    linhas += [
        "## 1. Sumário Geral",
        "",
        f"| Métrica | Valor |",
        f"|---|---|",
        f"| Total de eventos capturados | **{stats['total']}** |",
    ]
    for servico, qtd in stats["por_servico"].items():
        linhas.append(f"| Eventos — {servico.upper()} | {qtd} |")
    linhas += ["", "---", ""]

    # Gráfico por serviço
    _embutir_grafico(linhas, graficos, "01_por_servico.png",
                     "Distribuição de eventos por serviço simulado")

    # IPs mais ativos
    linhas += [
        "## 2. IPs Mais Ativos",
        "",
        "| # | IP de Origem | Tentativas |",
        "|---|---|---|",
    ]
    for i, (ip, cnt) in enumerate(stats["top_ips"], 1):
        linhas.append(f"| {i} | `{ip}` | {cnt} |")
    linhas += [""]
    _embutir_grafico(linhas, graficos, "02_top_ips.png",
                     "Top IPs atacantes")
    linhas += ["---", ""]

    # Credenciais
    linhas += [
        "## 3. Credenciais Mais Testadas",
        "",
        "### 3.1 Top usuários",
        "",
        "| # | Usuário | Ocorrências |",
        "|---|---|---|",
    ]
    for i, (u, c) in enumerate(stats["top_usuarios"], 1):
        linhas.append(f"| {i} | `{u}` | {c} |")

    linhas += ["", "### 3.2 Top senhas", "",
               "| # | Senha | Ocorrências |",
               "|---|---|---|"]
    for i, (p, c) in enumerate(stats["top_senhas"], 1):
        linhas.append(f"| {i} | `{p}` | {c} |")

    linhas += ["", "### 3.3 Top pares usuário/senha", "",
               "| # | Par (usuário/senha) | Tentativas |",
               "|---|---|---|"]
    for i, ((u, p), c) in enumerate(stats["top_pares"], 1):
        linhas.append(f"| {i} | `{u}` / `{p}` | {c} |")
    linhas += [""]
    _embutir_grafico(linhas, graficos, "03_top_credenciais.png",
                     "Pares usuário/senha mais testados")
    linhas += ["---", ""]

    # Atividade por hora
    linhas += [
        "## 4. Horários de Pico",
        "",
    ]
    if stats["atividade_hora"]:
        hora_pico = max(stats["atividade_hora"], key=stats["atividade_hora"].get)
        linhas.append(
            f"> Hora com maior atividade: **{hora_pico}h** "
            f"({stats['atividade_hora'][hora_pico]} eventos)"
        )
    linhas += [""]
    _embutir_grafico(linhas, graficos, "04_atividade_hora.png",
                     "Atividade distribuída por hora do dia")
    linhas += ["---", ""]

    # HTTP
    if stats["top_http_paths"]:
        linhas += [
            "## 5. Paths HTTP Mais Requisitados",
            "",
            "| # | Requisição | Contagem |",
            "|---|---|---|",
        ]
        for i, (path, cnt) in enumerate(stats["top_http_paths"], 1):
            linhas.append(f"| {i} | `{path}` | {cnt} |")
        linhas += [""]
        _embutir_grafico(linhas, graficos, "05_top_http_paths.png",
                         "Paths HTTP mais acessados")
        linhas += ["---", ""]

    # Comandos SSH
    if stats["top_comandos"]:
        linhas += [
            "## 6. Comandos SSH Digitados",
            "",
            "| # | Comando | Ocorrências |",
            "|---|---|---|",
        ]
        for i, (cmd, cnt) in enumerate(stats["top_comandos"], 1):
            linhas.append(f"| {i} | `{cmd}` | {cnt} |")
        linhas += [""]
        _embutir_grafico(linhas, graficos, "06_top_comandos.png",
                         "Comandos mais executados no shell falso")
        linhas += ["---", ""]

    # Conclusão / Interpretação
    linhas += [
        "## 7. Interpretação dos Resultados",
        "",
        "Os dados capturados pelo honeypot revelam padrões típicos de ataques "
        "automatizados observados em ambientes reais:",
        "",
        "- **Credential stuffing / brute-force**: a maioria das tentativas usa "
        "credenciais padrão de fábrica (`root/root`, `admin/admin`) e senhas "
        "triviais (`123456`, `password`). Ferramentas como *Hydra* e *Medusa* "
        "são frequentemente usadas para automatizar esse processo.",
        "",
        "- **Reconhecimento pós-acesso**: os comandos mais digitados no shell "
        "falso (`whoami`, `id`, `uname -a`, `cat /etc/passwd`) são tipicamente "
        "os primeiros passos de um atacante que obtém acesso inicial — busca "
        "de informações sobre o sistema e nível de privilégio.",
        "",
        "- **Varredura de aplicações web**: os paths HTTP mais acessados "
        "(`/wp-login.php`, `/.env`, `/phpmyadmin`, `/admin`) indicam scanners "
        "automatizados procurando vulnerabilidades conhecidas em WordPress, "
        "painéis de administração e arquivos de configuração expostos.",
        "",
        "- **Concentração horária**: a distribuição por hora revela que ataques "
        "automatizados ocorrem de forma contínua, independentemente do horário, "
        "evidenciando o uso de bots e scripts.",
        "",
        "---",
        "",
        "## 8. Considerações Éticas e Legais",
        "",
        "O uso de honeypots levanta questões importantes que devem ser "
        "observadas em qualquer implantação real:",
        "",
        "| Aspecto | Orientação |",
        "|---|---|",
        "| **Isolamento** | O honeypot nunca deve ter acesso a sistemas de produção ou dados reais. |",
        "| **Responsabilidade legal** | Capturar tráfego de terceiros pode ser regulado por legislação local (ex.: LGPD no Brasil, GDPR na Europa). |",
        "| **Divulgação** | Dados coletados devem ser usados apenas para fins defensivos/acadêmicos, nunca publicados com IPs reais sem anonimização. |",
        "| **Transparência** | Documentar e comunicar ao gestor de TI/segurança qualquer implantação de honeypot em redes corporativas. |",
        "| **Não retaliar** | O objetivo é observar, nunca contra-atacar IPs identificados. |",
        "",
        "---",
        "",
        "*Relatório gerado automaticamente por `analisar_logs.py` — "
        "Projeto Final de Segurança Computacional.*",
    ]

    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas))

    print(f"  [relatório] {caminho}")
    return caminho


def _embutir_grafico(linhas: list, graficos: list[str], nome_arquivo: str,
                     legenda: str):
    """Adiciona linha de imagem Markdown se o gráfico foi gerado."""
    for g in graficos:
        if g.endswith(nome_arquivo):
            linhas.append(f"![{legenda}]({nome_arquivo})")
            linhas.append("")
            return


# ──────────────────────────────────────────────────────────────────────────────
# Saída no terminal (resumo rápido)
# ──────────────────────────────────────────────────────────────────────────────

def imprimir_resumo(stats: dict):
    print("\n" + "=" * 60)
    print("   RESUMO — ANÁLISE DO HONEYPOT")
    print("=" * 60)
    print(f"\nTotal de eventos capturados : {stats['total']}")
    print("\nPor serviço:")
    for s, q in stats["por_servico"].items():
        print(f"  {s.upper():6s} → {q} eventos")

    if stats["top_ips"]:
        print("\nTop 5 IPs atacantes:")
        for ip, cnt in stats["top_ips"][:5]:
            print(f"  {ip:<20} {cnt} tentativas")

    if stats["top_pares"]:
        print("\nTop 5 credenciais (usuário/senha):")
        for (u, p), cnt in stats["top_pares"][:5]:
            print(f"  {u}/{p:<20} {cnt}×")

    if stats["top_comandos"]:
        print("\nTop 5 comandos SSH:")
        for cmd, cnt in stats["top_comandos"][:5]:
            print(f"  {cmd:<25} {cnt}×")

    if stats["atividade_hora"]:
        hora_pico = max(stats["atividade_hora"], key=stats["atividade_hora"].get)
        print(f"\nHorário de pico : {hora_pico}h "
              f"({stats['atividade_hora'][hora_pico]} eventos)")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Ponto de entrada
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analisa logs do honeypot e gera relatório + gráficos."
    )
    parser.add_argument("--log", default=DEFAULT_LOG,
                        help=f"Caminho para o arquivo de log (padrão: {DEFAULT_LOG})")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help=f"Diretório de saída (padrão: {DEFAULT_OUT}/)")
    args = parser.parse_args()

    print(f"\n[*] Carregando eventos de: {args.log}")
    eventos = carregar_eventos(args.log)
    if not eventos:
        print("[!] Nenhum evento encontrado. Execute o honeypot e o simulador primeiro.")
        return

    print(f"[*] {len(eventos)} eventos carregados.")
    stats = calcular_estatisticas(eventos)
    imprimir_resumo(stats)

    print("[*] Gerando gráficos...")
    graficos = gerar_graficos(stats, args.out)

    print("[*] Gerando relatório Markdown...")
    relatorio = gerar_relatorio_md(stats, graficos, args.out, args.log)

    print(f"\n✅ Análise concluída! Arquivos gerados em: {args.out}/")
    print(f"   Relatório: {relatorio}")
    print(f"   Gráficos : {len(graficos)} arquivo(s)\n")


if __name__ == "__main__":
    main()
