############################################################
### PREBUILD STAGE #########################################
############################################################

FROM i386/ubuntu:18.04 as prebuild

# install Kitware's APT repo (for CMake)
RUN apt update && apt install -y apt-transport-https ca-certificates gnupg software-properties-common wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \ 
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

RUN apt-get update && apt-get install -y \
    clang-10 \
    cmake \
    gcc \
    g++ \
    ninja-build \
    patch \
    && rm -rf /var/lib/apt/lists/*

############################################################
### retrieve LLVM source tree

ADD https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz /usr/local/src
ADD https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang-10.0.1.src.tar.xz /usr/local/src

WORKDIR /usr/local/src
RUN tar -xf llvm-10.0.1.src.tar.xz && rm llvm-10.0.1.src.tar.xz

WORKDIR /usr/local/src/llvm-10.0.1.src/tools
RUN tar -xf ../../clang-10.0.1.src.tar.xz && rm ../../clang-10.0.1.src.tar.xz

############################################################
### add ropfuscator (essential files for build)

WORKDIR /usr/local/src/ropfuscator/
COPY cmake/ropfuscator-buildonly.cmake ./cmake/ropfuscator.cmake
COPY src/ ./src/
COPY patch/llvm-10.patch ./
COPY thirdparty/fmt/include/ ./thirdparty/fmt/include/
COPY thirdparty/tinytoml/include/ ./thirdparty/tinytoml/include/

WORKDIR /usr/local/src/llvm-10.0.1.src/lib/Target/X86
RUN ln -s ../../../../ropfuscator .
RUN patch < ropfuscator/llvm-10.patch && rm ropfuscator/llvm-10.patch

############################################################
### configure LLVM + ropfuscator

WORKDIR /usr/local/src/build-ropfuscator
RUN cmake \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang-10 \
    -DCMAKE_CXX_COMPILER=clang++-10 \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -GNinja \
    /usr/local/src/llvm-10.0.1.src


############################################################
### BUILD STAGE ############################################
############################################################

FROM i386/ubuntu:18.04 as build

# install Kitware's APT repo (for CMake)
RUN apt update && apt install -y apt-transport-https ca-certificates gnupg software-properties-common wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \ 
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

RUN apt-get update && apt-get install -y \
    clang-10 \
    cmake \
    gcc \
    g++ \
    ninja-build \
    patch \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=prebuild /usr/local/src/ /usr/local/src/

############################################################
### build LLVM + ropfuscator

WORKDIR /usr/local/src/build-ropfuscator
RUN ninja llc clang

############################################################
### add ropfuscator (extra files)

WORKDIR /usr/local/src/ropfuscator/
COPY cmake/ropfuscator.cmake ./cmake/ropfuscator.cmake
COPY CMakeLists.txt ./
COPY examples/ ./examples/
COPY evaluation/ ./evaluation/
COPY binutils/ ./binutils/
COPY configs/ ./configs/
COPY testcase/ ./testcase/
COPY librop/ ./librop
COPY thirdparty/chocolate-doom ./thirdparty/chocolate-doom

# reload CMakeLists.txt
RUN touch /usr/local/src/llvm-10.0.1.src/lib/Target/X86/CMakeLists.txt
WORKDIR /usr/local/src/build-ropfuscator
RUN ninja llc clang
RUN strip -s bin/llc bin/clang


############################################################
### RELEASE IMAGE ##########################################
############################################################

FROM i386/ubuntu:18.04 as runtime

# install Kitware's APT repo (for CMake)
RUN apt update && apt install -y apt-transport-https ca-certificates gnupg software-properties-common wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \ 
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y \
    clang-10 \
    cmake \
    gcc \ 
    g++ \
    libsdl2-mixer-dev \
    libsdl2-net-dev \
    libsdl2-dev \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/src/build-ropfuscator/bin/llc /usr/local/bin/
COPY --from=build /usr/local/src/build-ropfuscator/bin/clang-10 /usr/local/bin/

RUN ln -s /usr/lib/clang /usr/local/lib/clang
