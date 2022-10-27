FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    bash-completion \
    binutils \
    build-essential \
    clang-12 \
    cmake \
    curl \
    file \
    git \
    gpg \
    jq \
    libcap-dev \
    llvm-12 \
    openjdk-11-jdk \
    python-is-python3 \
    python3 \
    vim \
    wget

RUN curl --fail --silent --show-error --location -o go.tar.gz https://go.dev/dl/go1.19.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin"
ENV PATH="${PATH}:/usr/lib/llvm-12/bin"
ENV CC=/usr/lib/llvm-12/bin/clang
ENV CXX=/usr/lib/llvm-12/bin/clang++

RUN groupadd user && useradd --no-log-init -m -s /bin/bash -g user user
USER user

COPY --chown=user:user . /home/user/cifuzz-git
WORKDIR /home/user/cifuzz-git

ENV SHELL=/bin/bash
RUN go run tools/builder/builder.go --version dev --verbose && \
    go build -tags installer -o cifuzz-installer cmd/installer/installer.go && \
    ./cifuzz-installer --verbose
ENV PATH="${PATH}:/home/user/cifuzz/bin"
