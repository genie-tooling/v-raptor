# Use a standard base image
FROM ubuntu:24.04

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python, Git, and other essentials
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    ninja-build \
    python3 \
    python3-pip \
    pipx \
    git \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Install security tools
# Python tools
RUN pipx install semgrep && \
    pipx install bandit

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

# Install Python dependencies using uv
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"
RUN rm -rf .venv
RUN uv venv
RUN uv pip install .

# Expose the web server port
EXPOSE 5000

# A command to keep the container running if started directly
CMD ["tail", "-f", "/dev/null"]
