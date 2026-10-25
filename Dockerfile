# CryWirelessMV Dockerfile
# NOTE: For wireless attacks (monitor mode, deauth), this container MUST be run with:
#   docker run --privileged --net=host -v /dev/bus/usb:/dev/bus/usb crywireless
# Without a passed-through USB Wi-Fi adapter, only the CLI menu and non-hardware features will work.

FROM python:3.11-slim

# Install system dependencies required by CryWirelessMV
RUN apt-get update && apt-get install -y \
    aircrack-ng \
    iw \
    iproute2 \
    net-tools \
    wireless-tools \
    bluez \
    bluetooth \
    hcxtools \
    build-essential \
    python3-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv
RUN pip install uv

# Copy dependency files first (for Docker layer caching)
COPY pyproject.toml uv.lock ./

# Install Python dependencies
RUN uv sync --no-dev

# Copy the rest of the source code
COPY . .

# Default command (will require --privileged and --net=host to actually function)
ENTRYPOINT ["uv", "run", "python", "main.py"]
