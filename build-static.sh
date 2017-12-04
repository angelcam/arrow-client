#!/bin/bash

# Initialization (do not change)

WORK_DIR=`pwd`
SELF_DIR=`dirname $0`
SELF_DIR=`readlink -e $SELF_DIR`

# Change the following variables as needed

RUST_TARGET=arm-unknown-linux-musleabi

OPENSSL_TARGET=linux-armv4

TOOLCHAIN_PREFIX=arm-hisiv300-linux-uclibcgnueabi-
TOOLCHAIN_DIR=$SELF_DIR/toolchains/arm-hisiv300-linux

# Do not touch the following variables unless necessary

MUSL_VERSION=1.1.18
OPENSSL_VERSION=1.1.0g

MUSL_URL=https://www.musl-libc.org/releases/musl-${MUSL_VERSION}.tar.gz
OPEN_SSL_URL=https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz

TOOLCHAIN_BIN=$TOOLCHAIN_DIR/bin

# Set up the build environment

BUILD_DIR=$SELF_DIR/static-build

if [ ! -d $BUILD_DIR ]; then
  mkdir $BUILD_DIR
fi

export PATH=$TOOLCHAIN_BIN:$PATH

# Build static MUSL

MUSL_DIR=$BUILD_DIR/musldist
MUSL_BIN=$MUSL_DIR/bin
MUSL_LIB=$MUSL_DIR/lib
MUSL_INC=$MUSL_DIR/include

if [ ! -d $MUSL_DIR ]; then
  mkdir $MUSL_DIR
fi

cd $BUILD_DIR

if [ ! -f musl-${MUSL_VERSION}.tar.gz ]; then
  wget $MUSL_URL
fi

if [ ! -d musl-${MUSL_VERSION} ]; then
  tar xf musl-${MUSL_VERSION}.tar.gz
fi

cd musl-${MUSL_VERSION}

export CROSS_COMPILE=$TOOLCHAIN_PREFIX

if [ ! -f config.mak ]; then
  ./configure --target=$RUST_TARGET --prefix=$MUSL_DIR --disable-shared
fi

make
make install

unset CROSS_COMPILE

export PATH=$MUSL_BIN:$PATH

cd $SELF_DIR

# Build OpenSSL

cd $BUILD_DIR

if [ ! -f openssl-${OPENSSL_VERSION}.tar.gz ]; then
  wget $OPEN_SSL_URL
fi

if [ ! -d openssl-${OPENSSL_VERSION} ]; then
  tar xf openssl-${OPENSSL_VERSION}.tar.gz
fi

cd openssl-${OPENSSL_VERSION}

if [ -d "apps" ]; then
  mv "apps" "apps.old"
fi

if [ -d "fuzz" ]; then
  mv "fuzz" "fuzz.old"
fi

if [ -d "test" ]; then
  mv "test" "test.old"
fi

export AR=${TOOLCHAIN_PREFIX}ar
export CC=musl-gcc
export RANLIB=${TOOLCHAIN_PREFIX}ranlib

if [ ! -f .configured ]; then
  ./Configure $OPENSSL_TARGET no-filenames no-shared no-async no-comp no-deprecated no-dso no-ec no-ec2m no-engine no-hw-padlock no-ssl3-method no-bf no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dsa no-ecdsa no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 no-scrypt no-seed no-whirlpool no-threads --prefix=$MUSL_DIR
  touch .configured
fi

make
make install_sw

unset AR
unset CC
unset RANLIB

cd $SELF_DIR

# Build the Arrow Client

export OPENSSL_STATIC=1
export OPENSSL_LIB_DIR=$MUSL_LIB
export OPENSSL_INCLUDE_DIR=$MUSL_INC

export CC_${RUST_TARGET//-/_}=musl-gcc

cargo build -v --target $RUST_TARGET --release

${TOOLCHAIN_PREFIX}"strip" target/$RUST_TARGET/release/arrow-client
