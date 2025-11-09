# Use a standard base image
FROM ubuntu:22.04

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python, Git, and other essentials
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    ninja-build \
    python3 \
    python3-pip \
    git \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Install security tools
# Python tools
RUN pip3 install --no-cache-dir semgrep bandit

# Install gitleaks
RUN GITLEAKS_VERSION=$(curl -s "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep -oP '"tag_name": "v\K[0-9.]+' | head -n 1) && \
    curl -L -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/gitleaks && \
    rm gitleaks.tar.gz

# Create a working directory
WORKDIR /app

# Copy the application code
COPY . /app

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Expose the web server port
EXPOSE 5000

# A command to keep the container running if started directly
CMD ["tail", "-f", "/dev/null"]
