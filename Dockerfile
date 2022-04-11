############################################################
### BUILD STAGE #########################################
############################################################

FROM ubuntu:18.04 as build

# install Kitware's APT repo (for CMake)
RUN apt update && apt install -y apt-transport-https ca-certificates gnupg software-properties-common wget && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

RUN apt-get update && apt-get install -y build-essential git cmake ninja-build patch && rm -rf /var/lib/apt/lists/*

############################################################
### retrieve LLVM source tree

ADD https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-10.0.1.src.tar.xz /usr/local/src
ADD https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang-10.0.1.src.tar.xz /usr/local/src

WORKDIR /usr/local/src
RUN tar -xf llvm-10.0.1.src.tar.xz && rm llvm-10.0.1.src.tar.xz

WORKDIR /usr/local/src/llvm-10.0.1.src/tools
RUN tar -xf ../../clang-10.0.1.src.tar.xz && rm ../../clang-10.0.1.src.tar.xz

#############################################################
#### add ropfuscator (essential files for build)
#
WORKDIR /usr/local/src/llvm-10.0.1.src/lib/Target/X86/ropfuscator
COPY cmake/ropfuscator.cmake ./cmake/ropfuscator.cmake
COPY src/ ./src/
COPY patches/ropfuscator_pass.patch ./
COPY thirdparty/ ./thirdparty

WORKDIR /usr/local/src/llvm-10.0.1.src/lib/Target/X86
RUN patch < ropfuscator/ropfuscator_pass.patch && rm ropfuscator/ropfuscator_pass.patch

#############################################################
#### configure LLVM + ropfuscator
#

WORKDIR /usr/local/src/build-ropfuscator
RUN cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD=X86 \
  -GNinja \
  /usr/local/src/llvm-10.0.1.src

###########################################################
## build LLVM + ropfuscator

RUN ninja 
#RUN strip -s bin/llc bin/clang

############################################################
### RELEASE IMAGE ##########################################
############################################################

FROM ubuntu:18.04 as runtime

# install Kitware's APT repo (for CMake)
RUN apt update && apt install -y apt-transport-https ca-certificates gnupg software-properties-common wget && \
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \
apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y gcc-multilib g++-multilib cmake libsdl2-mixer-dev libsdl2-net-dev libsdl2-dev libc6 libc6-dev

COPY --from=build /usr/local/src/ /usr/local/src

WORKDIR /usr/local/src/build-ropfuscator
RUN cmake --install .

RUN update-alternatives --install /usr/bin/cc cc /usr/local/bin/clang 100
RUN update-alternatives --install /usr/bin/c++ c++ /usr/local/bin/clang++ 100

CMD /bin/bash
