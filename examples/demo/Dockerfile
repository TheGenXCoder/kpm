FROM archlinux:latest

# Install Go and Git (the only deps — release binaries coming soon)
RUN pacman -Sy --noconfirm go git

# Install KPM using the same script users run
RUN curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.sh | bash

# Build mock-codex demo app
COPY mock-codex/ /tmp/mock-codex/
RUN cd /tmp/mock-codex && go build -o /usr/local/bin/mock-codex . && rm -rf /tmp/mock-codex

# Create template hierarchy directories
RUN mkdir -p /etc/catalyst9/.kpm/templates \
    && mkdir -p /root/.kpm/templates \
    && mkdir -p /app/.kpm/templates

# Certs and config are mounted at runtime
VOLUME ["/root/.kpm/certs"]

WORKDIR /app
ENTRYPOINT ["/bin/bash"]
