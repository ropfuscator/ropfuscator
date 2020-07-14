#!/bin/sh

CWD=$(dirname $(realpath $0))
ROPCC=$CWD/../../../ropcc.sh

rm -rf libdvdcss-1.4.2 libdvdcss-1.4.2.tar.bz2 build
wget https://download.videolan.org/pub/libdvdcss/1.4.2/libdvdcss-1.4.2.tar.bz2
tar -xf libdvdcss-1.4.2.tar.bz2

mkdir -p build
cd build
$ROPCC cc -c -I.. ../libdvdcss-1.4.2/src/ioctl.c     -o ioctl.o     2>&1 | tee -a build.log
$ROPCC cc -c -I.. ../libdvdcss-1.4.2/src/error.c     -o error.o     2>&1 | tee -a build.log
$ROPCC cc -c -I.. ../libdvdcss-1.4.2/src/device.c    -o device.o    2>&1 | tee -a build.log
$ROPCC cc -c -I.. ../libdvdcss-1.4.2/src/css.c       -o css.o       2>&1 | tee -a build.log
$ROPCC cc -c -I.. ../libdvdcss-1.4.2/src/libdvdcss.c -o libdvdcss.o 2>&1 | tee -a build.log
$ROPCC cc -shared -ropfuscator-config=../ropf/plain.conf    ioctl.o error.o device.o css.o libdvdcss.o -o libdvdcss_plain.so    2>&1 | tee -a build.log
$ROPCC cc -shared -ropfuscator-config=../ropf/roponly.conf  ioctl.o error.o device.o css.o libdvdcss.o -o libdvdcss_roponly.so  2>&1 | tee -a build.log
$ROPCC cc -shared -ropfuscator-config=../ropf/opaque.conf   ioctl.o error.o device.o css.o libdvdcss.o -o libdvdcss_opaque.so   2>&1 | tee -a build.log
$ROPCC cc -shared -ropfuscator-config=../ropf/stegano.conf  ioctl.o error.o device.o css.o libdvdcss.o -o libdvdcss_stegano.so  2>&1 | tee -a build.log
$ROPCC cc -shared -ropfuscator-config=../ropf/balanced.conf ioctl.o error.o device.o css.o libdvdcss.o -o libdvdcss_balanced.so 2>&1 | tee -a build.log
cd ..
