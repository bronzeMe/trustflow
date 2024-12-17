# Copyright 2024 Ant Group Co., Ltd.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG BASE_IMAGE=occlum/hyperenclave:0.27.13-hypermode-1.3.0-ubuntu22.04
FROM ${BASE_IMAGE}

LABEL maintainer="secretflow-contact@service.alipay.com"

# change dash to bash as default shell
RUN ln -sf /usr/bin/bash /bin/sh



RUN apt update && DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt install -y \
    tzdata \ 
    build-essential \
    ocaml \
    automake \
    autoconf \
    libtool \
    wget \
    python-is-python3 \
    python3-pip \
    libssl-dev \
    npm \
    git \
    debhelper \
    zip \ 
    libcurl4-openssl-dev \
    pkgconf \ 
    libboost-dev \ 
    libboost-system-dev \ 
    libboost-thread-dev \
    protobuf-c-compiler \
    libprotobuf-c-dev \
    vim \
    golang \
    cmake \
    ninja-build  \
    curl \
    ssh \
    llvm-dev libclang-dev clang \
    rsync \
    libfuse2 \
    && rm -f /etc/ssh/ssh_host_* \
    && apt clean 

# instal protoc v3.19.4
RUN curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-linux-x86_64.zip \
   && unzip protoc-3.19.4-linux-x86_64.zip -d /root/.local && echo 'export PATH="/root/.local/bin:$PATH"' >> /root/.bashrc \
   && rm -f protoc-3.19.4-linux-x86_64.zip


# install conda
RUN wget http://repo.anaconda.com/miniconda/Miniconda3-py310_24.4.0-0-Linux-x86_64.sh \
  && bash Miniconda3-py310_24.4.0-0-Linux-x86_64.sh -b && rm -f Miniconda3-py310_24.4.0-0-Linux-x86_64.sh \
  && ln -sf /root/miniconda3/bin/conda /usr/bin/conda \
  && conda init


# install bazelisk 
RUN npm install -g @bazel/bazelisk

# install emsdk
RUN git clone https://github.com/emscripten-core/emsdk.git /opt/emsdk && cd /opt/emsdk \
    && ./emsdk install latest && ./emsdk activate latest && echo "source /opt/emsdk/emsdk_env.sh" >> /root/.bashrc


# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
RUN curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin
