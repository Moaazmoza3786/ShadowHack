FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install cybersecurity tools
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    nmap \
    netcat-traditional \
    nikto \
    gobuster \
    hyrdra \
    metasploit-framework \
    curl \
    git \
    vim \
    python3-pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add a welcome message and aliases
RUN echo 'alias ll="ls -la"' >> /etc/bash.bashrc \
    && echo 'echo "Welcome to Study Hub Advanced Lab Environment!"' >> /etc/bash.bashrc
