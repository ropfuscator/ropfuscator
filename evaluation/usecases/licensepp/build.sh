#!/bin/sh

CWD=$(dirname $(realpath $0))
ROPCC=$CWD/../../../ropcc.sh

LICENSEPP_SOURCE="
    src/external/Ripe.cc
    src/utils.cc
    src/json-object.cc
    src/crypto/aes.cc
    src/crypto/base64.cc
    src/crypto/base16.cc
    src/crypto/rsa.cc
    src/issuing-authority.cc
    src/license.cc
    sample/main.cc
"

rm -rf licensepp* cryptopp*

wget https://github.com/amrayn/licensepp/archive/v1.0.6.zip -O licensepp-1.0.6.zip
wget https://github.com/weidai11/cryptopp/archive/CRYPTOPP_8_2_0.zip -O cryptopp-8.2.0.zip
wget https://github.com/amraynweb/cryptopp-pem/archive/CRYPTOPP_8_2_0.zip -O cryptopp-pem-8.2.0.zip
unzip licensepp-1.0.6.zip
unzip cryptopp-8.2.0.zip
unzip cryptopp-pem-8.2.0.zip
mv licensepp-1.0.6 licensepp
mv cryptopp-CRYPTOPP_8_2_0 cryptopp
cp cryptopp-pem-CRYPTOPP_8_2_0/* cryptopp/
rm -r cryptopp-pem-CRYPTOPP_8_2_0

cd cryptopp
CXX=$ROPCC CXXFLAGS="c++ -DCRYPTOPP_DISABLE_ASM -O1 -flto" make libcryptopp.a
cd ..

cd licensepp
mkdir -p build
cd build

OBJS=""
for src in $LICENSEPP_SOURCE; do
    obj=$(basename ${src%.*}).o
    $ROPCC c++ -c -O1 -flto -I../.. -I.. -DLICENSEPP_SOVERSION=1.0.6 -DRIPE_VERSION=\"4.0.1-custom-static\" ../$src -o $obj 2>&1 | tee -a build.log
    OBJS="$OBJS $obj"
done

$ROPCC c++ -ropfuscator-config=../../ropf/plain.conf    -O1 -flto -Wl,--gc-sections $OBJS ../../cryptopp/libcryptopp.a -o license-manager-sample.plain    | tee -a build.log
$ROPCC c++ -ropfuscator-config=../../ropf/roponly.conf  -O1 -flto -Wl,--gc-sections $OBJS ../../cryptopp/libcryptopp.a -o license-manager-sample.roponly  | tee -a build.log
$ROPCC c++ -ropfuscator-config=../../ropf/opaque.conf   -O1 -flto -Wl,--gc-sections $OBJS ../../cryptopp/libcryptopp.a -o license-manager-sample.opaque   | tee -a build.log
$ROPCC c++ -ropfuscator-config=../../ropf/stegano.conf  -O1 -flto -Wl,--gc-sections $OBJS ../../cryptopp/libcryptopp.a -o license-manager-sample.stegano  | tee -a build.log
$ROPCC c++ -ropfuscator-config=../../ropf/balanced.conf -O1 -flto -Wl,--gc-sections $OBJS ../../cryptopp/libcryptopp.a -o license-manager-sample.balanced | tee -a build.log

cd ../..
