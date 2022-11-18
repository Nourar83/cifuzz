FROM ubuntu:22.04
ARG UID=1000
ARG GID=1000

# Install APT packages with caching set up according to:
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
    clang \
    cmake \
    curl \
    fish \
    file \
    git \
    golang \
    gpg \
    gradle \
    lcov \
    jq \
    libc6-dev \
    libcap-dev \
    llvm \
    maven \
    openjdk-11-jdk \
    python-is-python3 \
    python3 \
    vim \
    zip \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Install Bazel
RUN --mount=type=cache,target=/var/cache/bazelisk \
    SHA256=$(sha256sum /var/cache/bazelisk/bazelisk | cut -d ' ' -f 1); \
    if [ "${SHA256:-}" != "19fd84262d5ef0cb958bcf01ad79b528566d8fef07ca56906c5c516630a0220b" ]; then \
      curl --fail --silent --show-error --location -o /var/cache/bazelisk/bazelisk https://github.com/bazelbuild/bazelisk/releases/download/v1.15.0/bazelisk-linux-amd64; \
    fi && \
    install -m755 /var/cache/bazelisk/bazelisk /usr/local/bin/bazel

RUN groupadd -g $GID -o user && useradd --no-log-init -m -s /usr/bin/zsh -u $UID -g $GID user
USER user

# Install cifuzz
COPY --chown=user:user build/bin/cifuzz_installer_linux /home/user/
RUN /home/user/cifuzz_installer_linux --verbose --bash-completion --zsh-completion --fish-completion
ENV PATH="${PATH}:/home/user/.local/bin"

RUN echo 'fpath=(/home/user/.local/share/cifuzz/share/cifuzz/completions/zsh $fpath)' >> ~/.zshrc && \
    echo "autoload -U compinit; compinit" >> ~/.zshrc

# Create user-owned volumes, which allows us to cache these directories
# at runtime (it requires to specify a named volume with these container
# paths in the docker run command).
RUN mkdir -p /home/user/.cache/go-build && \
    mkdir -p /home/user/go/pkg/mod
VOLUME /home/user/.cache/go-build
VOLUME /home/user/go/pkg/mod

# Add $GOPATH/bin to the PATH to allow tools installed via `go install`
# to be found (for example the buildozer dependency of our integration
# tests, which is installed via `go install` in our Makefile).
ENV PATH="${PATH}:/home/user/go/bin"
