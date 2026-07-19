# ──────────────────────────────────────────────────────────────────
# Dockerfile — Honeypot isolado em container
# ──────────────────────────────────────────────────────────────────
# Garante isolamento total: nenhum acesso à rede do host,
# nenhum dado real exposto. As portas são mapeadas apenas
# explicitamente ao rodar o container.
# ──────────────────────────────────────────────────────────────────

FROM python:3.11-slim

LABEL maintainer="Projeto Final - Segurança Computacional"
LABEL description="Honeypot isolado — servidor falso SSH/FTP/HTTP + painel"

WORKDIR /app

# Dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código fonte
COPY honeypot.py simular_ataques.py analisar_logs.py dashboard.py ./

# Diretório de logs (persistido via volume)
RUN mkdir -p logs relatorio

# Roda como usuário não-root (boa prática: o processo do honeypot
# nunca deveria ter privilégios de root dentro do container)
RUN useradd --create-home --shell /bin/bash honeypot \
    && chown -R honeypot:honeypot /app
USER honeypot

# Portas dos serviços falsos
EXPOSE 2222
EXPOSE 2121
EXPOSE 8080
# Porta do dashboard Streamlit
EXPOSE 8501

# Por padrão só sobe o honeypot. Para rodar o dashboard também,
# use `docker exec -d <container> streamlit run dashboard.py --server.address=0.0.0.0`
# ou troque o CMD abaixo pelo entrypoint.sh (ver README).
CMD ["python", "honeypot.py"]