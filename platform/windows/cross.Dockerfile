FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build make perl g++-mingw-w64-x86-64-posix ca-certificates libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*
