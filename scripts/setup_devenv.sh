#!/bin/bash

ROPFUSCATOR_PATH=`( cd $(dirname $0) && cd .. && pwd )`
LLVM_VERSION=llvm-10.0.0.src
CLANG_VERSION=clang-10.0.0.src

LLVM_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/$LLVM_VERSION.tar.xz
CLANG_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/$CLANG_VERSION.tar.xz

# download LLVM
wget $LLVM_URL
tar -xf $LLVM_VERSION.tar.xz && rm $LLVM_VERSION.tar.xz
cd $LLVM_VERSION
# insert clang inot LLVM source tree
pushd tools

wget $CLANG_URL
tar -xf $CLANG_VERSION.tar.xz  && rm $CLANG_VERSION.tar.xz

popd
# link ropfuscator dir into LLVM source tree
pushd lib/Target/X86

ln -s $ROPFUSCATOR_PATH .
patch < ropfuscator/patch/llvm-10.patch

popd
# create build dir
mkdir build && cd build
# config project
cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -G Ninja ..

