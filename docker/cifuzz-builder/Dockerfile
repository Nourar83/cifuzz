FROM ubuntu:20.04 AS build

# Install APT packages with caching set up according to
# https://docs.docker.com/engine/reference/builder/#example-cache-apt-packages
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
    export DEBIAN_FRONTEND=noninteractive && \
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
    wget \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="${PATH}:/usr/lib/llvm-12/bin"
ENV CC=/usr/lib/llvm-12/bin/clang
ENV CXX=/usr/lib/llvm-12/bin/clang++

# Install Go
RUN --mount=type=cache,target=/var/cache/go-src \
    SHA256=$(sha256sum /var/cache/go-src/go.tar.gz | cut -d ' ' -f 1); \
    if [ "${SHA256:-}" != "5e8c5a74fe6470dd7e055a461acda8bb4050ead8c2df70f227e3ff7d8eb7eeb6" ]; then \
      curl --fail --silent --show-error --location -o /var/cache/go-src/go.tar.gz https://go.dev/dl/go1.19.2.linux-amd64.tar.gz; \
    fi && \
    tar -C /usr/local -xzf /var/cache/go-src/go.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin"

WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    make installer

FROM scratch AS bin
COPY --from=build /src/build/bin/cifuzz_installer_linux /
