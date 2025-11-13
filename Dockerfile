FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++-13 \
    cmake \
    git \
    python3 \
    python3.12-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set g++-13 as default
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100

WORKDIR /apex

# Copy source code
COPY . .

# Initialize submodules (OpenFHE)
RUN git submodule update --init --recursive

# Build APEX
RUN cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_OPENMP=OFF \
    && cmake --build build -j$(nproc)

# Set library path for OpenFHE shared libraries
ENV LD_LIBRARY_PATH=/apex/build/lib

CMD ["/bin/bash"]
