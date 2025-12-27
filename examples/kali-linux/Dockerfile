# Use Kali Linux base image and install all security tools
FROM kalilinux/kali-rolling

# Set working directory
WORKDIR /app

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Set non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV DEBIAN_PRIORITY=critical

# Configure Kali repositories first
RUN echo "deb http://archive-4.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list && \
    echo "deb-src http://archive-4.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list

# Now update with correct repository and install packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    jq \
    ca-certificates \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# Switch to HTTPS repository after ca-certificates are installed
RUN echo "deb https://archive-4.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list && \
    echo "deb-src https://archive-4.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list

# Install ALL available kali-tools packages using wildcards
RUN apt-get update && \
    echo "Installing all available Kali tool packages..." && \
    apt-get install -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    kali-tools-* \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    gobuster \
    dirb \
    hydra \
    john \
    hashcat \
    metasploit-framework \
    burpsuite \
    wireshark \
    aircrack-ng \
    tcpdump \
    gdb \
    gdbserver \
    radare2 \
    binwalk \
    forensics-full \
    && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Create Python virtual environment and install Python dependencies
RUN python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt && \
    deactivate

# Copy server code
COPY kali_server.py .

# Copy tool discovery script
COPY tool_discovery.sh .

# Make discovery script executable
RUN chmod +x tool_discovery.sh

# Create non-root user but keep as root for security tools
RUN useradd -m -u 1000 mcpuser && \
    chown -R mcpuser:mcpuser /app

# Stay as root for security tools that require privileges
# USER mcpuser

# Update PATH to include virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Run server using virtual environment
CMD ["/opt/venv/bin/python", "kali_server.py"]