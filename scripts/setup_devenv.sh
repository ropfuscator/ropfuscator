#!/bin/bash

ROPFUSCATOR_PATH=`( cd $(dirname $0) && cd .. && pwd )`

VERSION="10.0.1"

LLVM_GITHUBORG="llvmorg-$VERSION"
LLVM_PKGNAME="llvm-$VERSION.src"
CLANG_PKGNAME="clang-$VERSION.src"
LLVM_TAR="$LLVM_PKGNAME.tar.xz"
CLANG_TAR="$CLANG_PKGNAME.tar.xz"

LLVM_URL=https://github.com/llvm/llvm-project/releases/download/$LLVM_GITHUBORG/$LLVM_TAR
CLANG_URL=https://github.com/llvm/llvm-project/releases/download/$LLVM_GITHUBORG/$CLANG_TAR

# download LLVM
wget $LLVM_URL
tar -xf $LLVM_TAR && rm $LLVM_TAR
cd $LLVM_PKGNAME
# insert clang inot LLVM source tree
pushd tools

wget $CLANG_URL
tar -xf $CLANG_TAR  && rm $CLANG_TAR

popd
# link ropfuscator dir into LLVM source tree
pushd lib/Target/X86

ln -s $ROPFUSCATOR_PATH .
patch < ropfuscator/patch/llvm-10.patch

popd
# create build dir
mkdir build && cd build
# config project
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -G Ninja ..

