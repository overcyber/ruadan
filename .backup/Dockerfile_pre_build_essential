FROM kalilinux/kali-rolling:latest

LABEL maintainer="Overcyber"
LABEL description="Ruadan - Kali Linux Enumeration Orchestrator with red-MPPO & Multi-LLM"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/red-mppo:/app/ruadan:/app:/bridge:/ruadan

# 1. Update repository and install required Kali enumeration tools & system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-termcolor \
    python3-yaml \
    python3-numpy \
    python3-requests \
    git \
    curl \
    wget \
    jq \
    procps \
    nmap \
    hydra \
    nikto \
    gobuster \
    whatweb \
    wafw00f \
    dnsrecon \
    sslscan \
    sslyze \
    smbclient \
    enum4linux \
    onesixtyone \
    nbtscan \
    dirb \
    cewl \
    nfs-common \
    cisco-torch \
    ident-user-enum \
    smtp-user-enum \
    dnsutils \
    iputils-ping \
    ca-certificates \
    davtest \
    snmp \
    libxml2-utils \
    libcrypt-ssleay-perl \
    libio-socket-ssl-perl \
    sqlmap \
    metasploit-framework \
    postgresql \
    postgresql-client \
    chromium \
    xvfb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 1b. Ferramentas de fuzzing/compilação/RPC (layer SEPARADA: não invalida o cache
# da layer acima, que é pesada ~2GB com metasploit; mudanças aqui são rápidas)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffuf \
    feroxbuster \
    gcc \
    python3-msgpack \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 2. Exploit-DB (SearchSploit)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && ln -sf /opt/exploitdb/searchsploit /usr/bin/searchsploit

# 3. AI & Orchestration dependencies
RUN pip3 install --no-cache-dir --break-system-packages \
    numpy pyyaml requests termcolor structlog defusedxml pydantic urllib3

WORKDIR /ruadan

# Copy application files
COPY . /ruadan/

# Install Ruadan package and setup executable
RUN python3 setup.py install || true && \
    printf '#!/usr/bin/env python3\nimport sys, os\nimport Ruadan2\nRuadan2.main()\n' > /usr/local/bin/ruadan && \
    chmod +x /usr/local/bin/ruadan && \
    chmod +x /ruadan/Ruadan2.py && \
    mkdir -p /ruadan/output /ruadan/targets

# NOTA: NÃO declarar VOLUME para /ruadan/targets|output aqui! A instrução VOLUME
# faz o Docker criar um volume ANÔNIMO VAZIO por cima desses paths em qualquer
# docker run sem mount explícito — mascarando o conteúdo montado do host e
# fazendo o Ruadan varrer o ALVO ERRADO (fallback hosts.txt fossil). Os mounts
# explícitos do docker-run.sh (-v .../targets:/ruadan/targets) são o mecanismo correto.

ENTRYPOINT ["python3", "/ruadan/Ruadan2.py"]
CMD ["--help"]
