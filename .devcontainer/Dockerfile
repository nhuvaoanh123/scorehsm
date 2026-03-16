# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Taktflow Systems
#
# Dev container image — matches CI exactly (ubuntu-24.04, Rust 1.87.0)
# No "works on my machine" — every contributor gets the same environment.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies (same as CI)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libudev-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update && apt-get install -y sudo \
    && echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

USER $USERNAME
WORKDIR /home/$USERNAME

# Install Rust — pinned to same version as rust-toolchain.toml and CI
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain 1.87.0 \
    --component rustfmt,clippy,llvm-tools-preview

ENV PATH="/home/$USERNAME/.cargo/bin:${PATH}"

# Install CI tools (same versions contributors and CI use)
RUN cargo install cargo-deny@0.16.3 \
    && cargo install cargo-llvm-cov@0.6.16

# Firmware cross-compile target (optional — for firmware contributors)
RUN rustup target add thumbv8m.main-none-eabihf

WORKDIR /workspaces/scorehsm
