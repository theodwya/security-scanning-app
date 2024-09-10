# Use Ubuntu as the base image for a more flexible environment
FROM ubuntu:22.04 AS builder

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    DEBIAN_FRONTEND=noninteractive \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# Ensure the build uses the root user
USER root

# Install system dependencies including Python, libmagic, and development libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libmagic1 \
    libmagic-dev \
    curl \
    git \
    tar \
    yara \
    clamav \
    build-essential \
    libssl-dev \
    libffi-dev \
    file \
    gcc \
    clamav-daemon \
    docker.io && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam

# Explicitly create necessary directories
RUN mkdir -p /app/uploads /app/output/scan-results

# Copy requirements.txt and install dependencies
COPY requirements.txt ./
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install YARA rules
RUN mkdir -p /opt/yara && \
    curl -o /opt/yara/malware_index.yar https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/malware_index.yar

# Set permissions for /app directories
RUN chown -R root:root /app

# Copy the application code and static files
COPY app.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# Stage 2: Production stage using the same Ubuntu base image
FROM ubuntu:22.04

# Ensure output and upload directories exist
RUN mkdir -p /app/output /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Set environment variables
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1 \
    YARA_RULES_PATH="/opt/yara/malware_index.yar" \
    FLASK_APP=app.py

# Ensure the production stage uses the root user
USER root

# Install Python and essential tools in the production stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    libmagic1 \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the virtual environment, Docker CLI, and application code from the builder stage
COPY --from=builder /app /app
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /opt/yara /opt/yara

# Set working directory
WORKDIR /app

# Fix the linking issue with libmagic
RUN ln -s /usr/lib/x86_64-linux-gnu/libmagic.so.1 /usr/lib/libmagic.so && \
    ldconfig  # Update shared library cache

# Expose the application port
EXPOSE 5000

# Correct the CMD to explicitly run app.py using Python
CMD ["python3", "/app/app.py"]
