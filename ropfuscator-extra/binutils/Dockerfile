FROM ubuntu:18.04

############################################################
### install build dependencies

RUN apt-get update && apt-get install -y \
    bison \
    clang-7 \
    flex \
    gcc-multilib \
    g++-multilib \
    python3 \
    python3-pip \
    texinfo \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir wllvm==1.2.7

RUN ln -s /usr/bin/clang-7 /usr/local/bin/clang && \
    ln -s /usr/bin/clang++-7 /usr/local/bin/clang++ && \
    ln -s /usr/bin/llvm-link-7 /usr/local/bin/llvm-link

############################################################
### retrieve package & config

WORKDIR /usr/src
ADD https://github.com/bminor/binutils-gdb/archive/binutils-2_34.tar.gz /usr/src
RUN mkdir -p /opt/binutils-bc

ENV CC="wllvm -m32" \
    CXX="wllvm++ -m32" \
    LLVM_COMPILER=clang \
    development=false

############################################################
### build gdbserver

RUN tar -zxf binutils-2_34.tar.gz
WORKDIR /usr/src/binutils-gdb-binutils-2_34/gdb/gdbserver

RUN ./configure --host=i686-linux --build=i686-linux --target=i686-linux && make
RUN extract-bc gdbserver && mv gdbserver.bc /opt/binutils-bc/gdbserver.bc && \
    extract-bc gdbreplay && mv gdbreplay.bc /opt/binutils-bc/gdbreplay.bc

WORKDIR /usr/src
RUN rm -rf /usr/src/binutils-gdb-binutils-2_34

############################################################
### build binutils / gdb

RUN tar -zxf binutils-2_34.tar.gz

WORKDIR /usr/src/binutils-gdb-binutils-2_34

RUN ./configure --host=i686-linux --build=i686-linux --target=i686-linux --disable-gdbserver && make

RUN extract-bc binutils/addr2line && mv binutils/addr2line.bc /opt/binutils-bc/addr2line.bc && \
    extract-bc binutils/ar && mv binutils/ar.bc /opt/binutils-bc/ar.bc && \
    extract-bc gas/as-new && mv gas/as-new.bc /opt/binutils-bc/as.bc && \
    extract-bc binutils/cxxfilt && mv binutils/cxxfilt.bc /opt/binutils-bc/c++filt.bc && \
    extract-bc binutils/elfedit && mv binutils/elfedit.bc /opt/binutils-bc/elfedit.bc && \
    extract-bc gdb/gdb && mv gdb/gdb.bc /opt/binutils-bc/gdb.bc && \
    extract-bc gprof/gprof && mv gprof/gprof.bc /opt/binutils-bc/gprof.bc && \
    extract-bc ld/ld-new && mv ld/ld-new.bc /opt/binutils-bc/ld.bc && \
    extract-bc binutils/nm-new && mv binutils/nm-new.bc /opt/binutils-bc/nm.bc && \
    extract-bc binutils/objcopy && mv binutils/objcopy.bc /opt/binutils-bc/objcopy.bc && \
    extract-bc binutils/objdump && mv binutils/objdump.bc /opt/binutils-bc/objdump.bc && \
    extract-bc binutils/ranlib && mv binutils/ranlib.bc /opt/binutils-bc/ranlib.bc && \
    extract-bc binutils/readelf && mv binutils/readelf.bc /opt/binutils-bc/readelf.bc && \
    extract-bc binutils/size && mv binutils/size.bc /opt/binutils-bc/size.bc && \
    extract-bc binutils/strings && mv binutils/strings.bc /opt/binutils-bc/strings.bc && \
    extract-bc binutils/strip-new && mv binutils/strip-new.bc /opt/binutils-bc/strip.bc

RUN rm -rf /usr/src/binutils-gdb-binutils-2_34

WORKDIR /opt/binutils-bc
