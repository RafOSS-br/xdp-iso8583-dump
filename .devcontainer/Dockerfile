FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        wget \
        gnupg \
        git \
        pkg-config \
        libelf-dev \
        libpcap-dev \
        libz-dev \
        iproute2 \
        iputils-ping \
        cmake \
        make \
        gcc \
        libc6-dev \
        lsb-release \
        software-properties-common \
        python3 \
        python3-pip \
        m4 \
        autoconf \
        automake \
        libtool \
        flex rsync netcat-openbsd \
        bison && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 16 && \
    rm llvm.sh

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-16 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-16 100 && \
    update-alternatives --install /usr/bin/llc llc /usr/bin/llc-16 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-16 100

RUN wget https://golang.org/dl/go1.21.13.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    rm go1.21.13.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
ENV GOPATH="/go"

RUN mkdir -p /kernel && \
    cd /kernel && \
    git clone --depth 1 --branch v5.15 https://github.com/torvalds/linux.git

ENV KERNEL_SOURCE=/kernel/linux
RUN cd ${KERNEL_SOURCE} && \
    make defconfig && \
    make headers_install
#make headers_install


RUN mkdir -p /sources && \
    cd /sources && \
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    cd bpftool/src && \
    make && make install PREFIX=/usr

RUN cd /sources && \
    git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git && \
    cd xdp-tools && \
    ./configure --prefix=/usr --includedir=${KERNEL_SOURCE}/include && \
    make && make install

RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

WORKDIR /workspace

# EXPOSE 8080

CMD [ "/bin/bash" ]
