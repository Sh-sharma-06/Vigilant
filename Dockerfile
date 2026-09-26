# Use a slim Python image to save space and reduce attack surface
FROM python:3.10-slim

# Install strace for kernel-level telemetry, iptables + iproute2 for network redirection
RUN apt-get update && apt-get install -y strace curl iptables iproute2 && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU directly to disk without caching
RUN pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu

# Set the working directory
WORKDIR /sandbox

# Keep the container alive until manually stopped by the runner
CMD ["tail", "-f", "/dev/null"]