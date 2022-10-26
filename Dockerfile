FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    bash-completion \
    binutils \
    build-essential \
    cmake \
    curl \
    file \
    git \
    gpg \
    gpg-agent \
    jq \
    libcap-dev \
    openjdk-11-jdk \
    python-is-python3 \
    python3 \
    vim \
    wget

RUN curl --fail --silent --show-error --location -o go.tar.gz https://go.dev/dl/go1.19.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz

RUN echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-14 main" > /etc/apt/sources.list.d/llvm.list && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    clang-14 llvm-14

ENV PATH="${PATH}:/usr/local/go/bin"
ENV PATH="${PATH}:/usr/lib/llvm-14/bin"
ENV CC=/usr/lib/llvm-14/bin/clang
ENV CXX=/usr/lib/llvm-14/bin/clang++

RUN groupadd user && useradd --no-log-init -m -s /bin/bash -g user user
USER user

COPY --chown=user:user . /home/user/cifuzz-git
WORKDIR /home/user/cifuzz-git

ENV SHELL=/bin/bash
RUN go run tools/builder/builder.go --version dev --verbose && \
    go build -tags installer -o cifuzz-installer cmd/installer/installer.go && \
    ./cifuzz-installer --verbose
ENV PATH="${PATH}:/home/user/cifuzz/bin"
