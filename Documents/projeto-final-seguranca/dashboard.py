"""
dashboard.py — Painel de Visualização em Tempo Real do Honeypot
=================================================================
Dashboard Streamlit que lê logs/eventos.json e mostra estatísticas
e gráficos atualizados, reaproveitando as funções já existentes em
analisar_logs.py (carregar_eventos, calcular_estatisticas).

Uso:
    streamlit run dashboard.py
    streamlit run dashboard.py -- --log logs/eventos.json

No Docker, exponha a porta 8501 e rode:
    docker exec -d honeypot streamlit run dashboard.py --server.address=0.0.0.0
"""

import time
import argparse
from datetime import datetime

import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd

from analisar_logs import carregar_eventos, calcular_estatisticas, PALETTE

# ──────────────────────────────────────────────────────────────────────────────
# Configuração da página
# ──────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Honeypot — Painel em Tempo Real",
    page_icon="🍯",
    layout="wide",
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="logs/eventos.json")
    # streamlit passa argumentos extras; ignoramos o que não reconhecemos
    args, _ = parser.parse_known_args()
    return args


ARGS = parse_args()


# ──────────────────────────────────────────────────────────────────────────────
# Sidebar — controles
# ──────────────────────────────────────────────────────────────────────────────

st.sidebar.title("🍯 Honeypot")
st.sidebar.caption("Painel de monitoramento em tempo real")

log_path = st.sidebar.text_input("Arquivo de log", value=ARGS.log)

auto_refresh = st.sidebar.checkbox("Atualizar automaticamente", value=True)
intervalo = st.sidebar.slider("Intervalo (segundos)", min_value=2, max_value=30,
                               value=5, disabled=not auto_refresh)

if st.sidebar.button("🔄 Atualizar agora"):
    st.rerun()

st.sidebar.divider()
st.sidebar.caption(
    "⚠️ Uso estritamente acadêmico. Dados coletados apenas em ambiente "
    "isolado/local, sem exposição de dados reais."
)


# ──────────────────────────────────────────────────────────────────────────────
# Carregar dados
# ──────────────────────────────────────────────────────────────────────────────

eventos = carregar_eventos(log_path)

st.title("🍯 Painel do Honeypot")
st.caption(f"Última atualização: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} "
           f"— fonte: `{log_path}`")

if not eventos:
    st.warning(
        "Nenhum evento encontrado ainda. Deixe o `honeypot.py` rodando e "
        "aguarde tentativas de conexão (ou rode `simular_ataques.py` para "
        "gerar dados de teste)."
    )
    if auto_refresh:
        time.sleep(intervalo)
        st.rerun()
    st.stop()

stats = calcular_estatisticas(eventos)

# Filtro por serviço (aplicado apenas na tabela de eventos brutos, para não
# distorcer as estatísticas gerais que a dupla já validou no relatório)
servicos_disponiveis = sorted(stats["por_servico"].keys())
filtro_servico = st.sidebar.multiselect(
    "Filtrar tabela por serviço", servicos_disponiveis, default=servicos_disponiveis
)


# ──────────────────────────────────────────────────────────────────────────────
# KPIs
# ──────────────────────────────────────────────────────────────────────────────

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total de eventos", stats["total"])
for col, serv in zip([col2, col3, col4], ["ssh", "ftp", "http"]):
    col.metric(serv.upper(), stats["por_servico"].get(serv, 0))

st.divider()


# ──────────────────────────────────────────────────────────────────────────────
# Helper para estilizar gráficos matplotlib no tema do dashboard
# ──────────────────────────────────────────────────────────────────────────────

def _estilo(ax):
    ax.spines[["top", "right"]].set_visible(False)


# ──────────────────────────────────────────────────────────────────────────────
# Linha 1 — eventos por serviço + atividade por hora
# ──────────────────────────────────────────────────────────────────────────────

c1, c2 = st.columns(2)

with c1:
    st.subheader("Eventos por Serviço")
    servicos = list(stats["por_servico"].keys())
    valores = list(stats["por_servico"].values())
    cores = [PALETTE.get(s, "#999") for s in servicos]
    fig, ax = plt.subplots(figsize=(5, 3.5))
    barras = ax.bar(servicos, valores, color=cores, edgecolor="white")
    ax.bar_label(barras, padding=3)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    _estilo(ax)
    st.pyplot(fig, clear_figure=True)

with c2:
    st.subheader("Atividade por Hora do Dia")
    horas = list(range(24))
    valores_h = [stats["atividade_hora"].get(h, 0) for h in horas]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.fill_between(horas, valores_h, alpha=0.25, color="#6BCB77")
    ax.plot(horas, valores_h, marker="o", color="#6BCB77", linewidth=2)
    ax.set_xticks(horas)
    ax.tick_params(axis="x", labelsize=7)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    _estilo(ax)
    st.pyplot(fig, clear_figure=True)


# ──────────────────────────────────────────────────────────────────────────────
# Linha 2 — top IPs + top credenciais
# ──────────────────────────────────────────────────────────────────────────────

c3, c4 = st.columns(2)

with c3:
    st.subheader("Top IPs Atacantes")
    if stats["top_ips"]:
        df_ips = pd.DataFrame(stats["top_ips"], columns=["IP", "Tentativas"])
        st.dataframe(df_ips, width="stretch", hide_index=True)
    else:
        st.info("Sem dados ainda.")

with c4:
    st.subheader("Credenciais Mais Testadas")
    if stats["top_pares"]:
        df_cred = pd.DataFrame(
            [(f"{u}/{p}", c) for (u, p), c in stats["top_pares"]],
            columns=["Usuário/Senha", "Tentativas"],
        )
        st.dataframe(df_cred, width="stretch", hide_index=True)
    else:
        st.info("Sem dados ainda.")


# ──────────────────────────────────────────────────────────────────────────────
# Linha 3 — comandos SSH + paths HTTP
# ──────────────────────────────────────────────────────────────────────────────

c5, c6 = st.columns(2)

with c5:
    st.subheader("Comandos SSH Digitados")
    if stats["top_comandos"]:
        df_cmd = pd.DataFrame(stats["top_comandos"], columns=["Comando", "Ocorrências"])
        st.dataframe(df_cmd, width="stretch", hide_index=True)
    else:
        st.info("Nenhum comando capturado ainda.")

with c6:
    st.subheader("Paths HTTP Requisitados")
    if stats["top_http_paths"]:
        df_http = pd.DataFrame(stats["top_http_paths"], columns=["Requisição", "Contagem"])
        st.dataframe(df_http, width="stretch", hide_index=True)
    else:
        st.info("Nenhuma requisição HTTP capturada ainda.")


# ──────────────────────────────────────────────────────────────────────────────
# Log de eventos ao vivo (mais recentes primeiro)
# ──────────────────────────────────────────────────────────────────────────────

st.divider()
st.subheader("📜 Eventos Recentes (ao vivo)")

eventos_filtrados = [e for e in eventos if e.get("servico") in filtro_servico]
eventos_recentes = list(reversed(eventos_filtrados))[:50]

if eventos_recentes:
    df_live = pd.DataFrame(eventos_recentes)
    colunas_ordem = [c for c in
                     ["timestamp", "servico", "ip", "porta_origem", "acao",
                      "usuario", "senha", "comandos", "request_line"]
                     if c in df_live.columns]
    st.dataframe(df_live[colunas_ordem], width="stretch", hide_index=True,
                 height=400)
else:
    st.info("Nenhum evento corresponde ao filtro selecionado.")


# ──────────────────────────────────────────────────────────────────────────────
# Auto-refresh (loop simples: espera e força um rerun do script)
# ──────────────────────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(intervalo)
    st.rerun()