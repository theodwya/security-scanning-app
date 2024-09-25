# Use Ubuntu as the base image for a more flexible environment
FROM ubuntu:22.04 AS builder

# Set environment variables for uploads, scan results, and others
ENV PATH="/app/venv/bin:$PATH" \
    DEBIAN_FRONTEND=noninteractive \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Ensure the build uses the root user
USER root

# Install system dependencies, Python, ClamAV, Trivy, and Grype
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

# Explicitly create necessary directories for uploads and scan results
RUN mkdir -p /app/uploads /app/output/scan-results

# Copy requirements.txt and install dependencies into a Python virtual environment
COPY requirements.txt ./
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Install Trivy for container scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Grype for vulnerability scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install YARA rules for malware detection
RUN mkdir -p /opt/yara && \
    curl -o /opt/yara/malware_index.yar https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/malware_index.yar

# Set permissions for the /app directory
RUN chown -R root:root /app

# Copy application code and static files
COPY app.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# Stage 2: Production stage using the same Ubuntu base image
FROM ubuntu:22.04

# Ensure output and upload directories exist and set proper permissions
RUN mkdir -p /app/output /app/uploads /app/output/scan-results && \
    chown -R root:root /app

# Set environment variables for file uploads, scan results, and YARA rules
ENV PATH="/app/venv/bin:$PATH" \
    UPLOAD_FOLDER=/app/uploads \
    SCAN_RESULTS_FOLDER=/app/output/scan-results \
    PYTHONUNBUFFERED=1 \
    YARA_RULES_PATH="/opt/yara/malware_index.yar" \
    FLASK_APP=app.py

# Ensure the production stage uses the root user
USER root

# Install Python and essential system dependencies in the production environment
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    libmagic1 \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the Python virtual environment, Docker CLI, and application files from the builder stage
COPY --from=builder /app /app
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /opt/yara /opt/yara

# Set the working directory
WORKDIR /app

# Fix linking issues with libmagic (file type recognition)
RUN ln -s /usr/lib/x86_64-linux-gnu/libmagic.so.1 /usr/lib/libmagic.so && \
    ldconfig  # Update shared library cache

# Expose the application port
EXPOSE 5000

# Run the Flask app using Python
CMD ["python3", "/app/app.py"]
