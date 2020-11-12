FROM bl4ck5un/sgx-docker:2.11
MAINTAINER Fan Zhang <bl4ck5unxx@gmail.com>

RUN apt-get update && apt-get --no-install-recommends install -y -qq \
    build-essential \
    automake \
    autoconf \
    libtool \
    libboost-program-options-dev \
    libboost-filesystem-dev \
    git \
    wget && \
    wget -q -O cmake-linux.sh https://github.com/Kitware/CMake/releases/download/v3.17.0/cmake-3.17.0-Linux-x86_64.sh && \
    sh cmake-linux.sh -- --skip-license && \
    rm cmake-linux.sh && \
    git clone --recurse-submodules -b v1.32.0 https://github.com/grpc/grpc && \
    mkdir -p grpc/cmake/build && \
    cd grpc/cmake/build && cmake -DgRPC_INSTALL=ON \
          -DgRPC_BUILD_TESTS=OFF \
          -DCMAKE_INSTALL_PREFIX=/opt/grpc \
          ../.. && make -j $(nproc) && make install && \
    apt-get --yes remove git wget && \
    apt-get --yes autoremove && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /grpc