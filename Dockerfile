# Use a standard base image
FROM ubuntu:24.04

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python, Git, Java (for PMD), and other essentials
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    ninja-build \
    python3 \
    python3-pip \
    pipx \
    git \
    curl \
    openjdk-17-jdk \
    unzip \
    ruby-full \
    nodejs \
    npm \
    golang-go \
    cppcheck && \
    rm -rf /var/lib/apt/lists/*

# Install PMD for code duplication analysis
RUN PMD_VERSION=6.55.0 && \
    curl -L -o pmd.zip "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" && \
    unzip pmd.zip && \
    rm pmd.zip && \
    mv pmd-bin-${PMD_VERSION} /opt/pmd

# Add PMD to PATH
ENV PATH="/opt/pmd/bin:$PATH"

# Install security and quality tools
# Python tools
RUN pipx install semgrep && \
    pipx install bandit && \
    pipx install pylint && \
    pipx install cohesion && \
    pipx install lizard && \
    pipx install njsscan

# Ruby
RUN gem install rubycritic && \
    gem install brakeman

# JavaScript
RUN npm install -g plato

# Go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN go install github.com/fzipp/gocyclo/cmd/gocyclo@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest

# Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh
RUN sh rustup-init.sh -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install --git https://github.com/mozilla/rust-code-analysis.git rust-code-analysis-cli

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