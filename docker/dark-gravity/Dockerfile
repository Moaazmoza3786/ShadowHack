# Operation: Dark Gravity - Vulnerable CTF Lab
# Docker configuration for PT1 Capstone Challenge

FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    libapache2-mod-php \
    vim \
    sudo \
    openssh-server \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create developer user
RUN useradd -m -s /bin/bash developer

# Create flags
RUN echo "AG{W3b_Sh3ll_M4st3r_2025}" > /home/developer/user.txt && \
    chmod 644 /home/developer/user.txt && \
    chown developer:developer /home/developer/user.txt

RUN echo "AG{R00t_Pr1vEsc_K1ng_2025}" > /root/root.txt && \
    chmod 600 /root/root.txt

# Configure sudoers for privilege escalation vulnerability
RUN echo "www-data ALL=(root) NOPASSWD: /usr/bin/vim" >> /etc/sudoers

# Create vulnerable upload portal
RUN mkdir -p /var/www/html/portal/uploads && \
    chown -R www-data:www-data /var/www/html/portal

# Copy vulnerable PHP files
COPY portal/ /var/www/html/portal/

# Configure Apache
RUN a2enmod php8.1 && \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Create index page
RUN echo '<!DOCTYPE html>\n\
<html>\n\
<head><title>Gravity Finance - Internal Server</title></head>\n\
<body style="font-family: Arial; background: #1a1a2e; color: white; text-align: center; padding: 50px;">\n\
<h1>⚠️ Gravity Finance Development Server</h1>\n\
<p>This server is for internal development only.</p>\n\
<p>Unauthorized access is prohibited.</p>\n\
</body>\n\
</html>' > /var/www/html/index.html

# SSH config
RUN mkdir /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config

# Expose ports
EXPOSE 80 22

# Start services
CMD service ssh start && service apache2 start && tail -f /var/log/apache2/access.log
