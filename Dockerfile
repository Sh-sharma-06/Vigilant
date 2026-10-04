# Use a slim Python image to save space and reduce attack surface
FROM python:3.10-slim

# Install only the tracing tool required by the sandbox runner.
RUN apt-get update && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

# Install the exact application dependencies, including the CPU PyTorch wheel.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Keep executable analysis code in the image; only the untrusted model folder
# is supplied as a read-only bind mount at runtime.
COPY run_model.py /sandbox/run_model.py

# The sandbox runner must never execute an untrusted model as root.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin runner

# Set the working directory
WORKDIR /sandbox
USER runner

# The host runner supplies the model-execution command.
CMD ["python", "run_model.py"]
