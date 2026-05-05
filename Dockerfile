FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    git \
    tshark \
    sleuthkit \
    libewf-dev \
    libvhdi-dev \
    libvmdk-dev \
    libbde-dev \
    libsmdev-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /traceforge

# Copy requirements and install
COPY requirements.txt .
RUN python3.11 -m pip install --upgrade pip && \
    python3.11 -m pip install -r requirements.txt

# Copy project
COPY . .

# Create data and reports directories
RUN mkdir -p /traceforge/data /traceforge/reports /traceforge/samples

# Default command — show help
ENTRYPOINT ["python3.11", "-m", "traceforge.cli"]
CMD ["--help"]
RUN ln -s /usr/bin/python3.11 /usr/local/bin/python3 && ln -s /usr/bin/python3.11 /usr/local/bin/python
