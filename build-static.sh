#!/bin/bash

##################################
# Initialization (do not change) #
##################################

set -e

WORK_DIR=`pwd`
SELF_DIR=`dirname $0`
SELF_DIR=`readlink -e $SELF_DIR`

############################################
# Change the following variables as needed #
############################################

BUILD_HOST=x86_64-unknown-linux-gnu

RUST_TARGET=arm-unknown-linux-musleabi

OPENSSL_TARGET=linux-armv4

KERNEL_HEADERS_ARCH=arm

FEATURE_DISCOVERY=1

TOOLCHAIN_PREFIX=arm-hisiv300-linux-uclibcgnueabi-
TOOLCHAIN_DIR=$SELF_DIR/toolchains/arm-hisiv300-linux

#########################################################
# Do not touch the following variables unless necessary #
#########################################################

MUSL_VERSION=1.1.18
OPENSSL_VERSION=1.1.0g
KERNEL_HEADERS_VERSION=3.12.6-5
LIBPCAP_VERSION=1.8.1

MUSL_URL=https://www.musl-libc.org/releases/musl-${MUSL_VERSION}.tar.gz
OPENSSL_URL=https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
KERNEL_HEADERS_URL=http://ftp.barfooze.de/pub/sabotage/tarballs/kernel-headers-${KERNEL_HEADERS_VERSION}.tar.xz
LIBPCAP_URL=http://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz

TOOLCHAIN_BIN=$TOOLCHAIN_DIR/bin

################################
# Set up the build environment #
################################

BUILD_DIR=$WORK_DIR/static-build

if [ ! -d $BUILD_DIR ]; then
  mkdir $BUILD_DIR
fi

export PATH=$TOOLCHAIN_BIN:$PATH

# Helper function for downloading and extracting a dependency
function fetch-dependency {
  if [ ! -d $1 ]; then
    if [ ! -f $2 ]; then
      wget $3
    fi
    tar xf $2
  fi
}

# Helper function for applying patches to a dependency
function apply-patches {
  if [ -d $SELF_DIR/patches/$1 ]; then
    for PATCH in $SELF_DIR/patches/$1/*.patch
    do
      patch -tN -p1 < $PATCH || true
    done
  fi
}

#####################
# Build static MUSL #
#####################

MUSL_DIR=$BUILD_DIR/musldist
MUSL_BIN=$MUSL_DIR/bin
MUSL_LIB=$MUSL_DIR/lib
MUSL_INC=$MUSL_DIR/include

if [ ! -d $MUSL_DIR ]; then
  mkdir $MUSL_DIR
fi

cd $BUILD_DIR

fetch-dependency \
  musl-${MUSL_VERSION} \
  musl-${MUSL_VERSION}.tar.gz \
  $MUSL_URL

cd musl-${MUSL_VERSION}

apply-patches musl-${MUSL_VERSION}

export CROSS_COMPILE=$TOOLCHAIN_PREFIX

if [ ! -f config.mak ]; then
  ./configure --target=$RUST_TARGET --prefix=$MUSL_DIR --disable-shared
fi

make
make install

unset CROSS_COMPILE

export PATH=$MUSL_BIN:$PATH

#################
# Build OpenSSL #
#################

cd $BUILD_DIR

fetch-dependency \
  openssl-${OPENSSL_VERSION} \
  openssl-${OPENSSL_VERSION}.tar.gz \
  $OPENSSL_URL

cd openssl-${OPENSSL_VERSION}

apply-patches openssl-${OPENSSL_VERSION}

rm -rf apps 2> /dev/null
rm -rf fuzz 2> /dev/null
rm -rf test 2> /dev/null

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

##################################
# Add kernel headers (if needed) #
##################################

if [ $FEATURE_DISCOVERY -eq 1 ]; then
  cd $BUILD_DIR

  fetch-dependency \
    kernel-headers-${KERNEL_HEADERS_VERSION} \
    kernel-headers-${KERNEL_HEADERS_VERSION}.tar.xz \
    $KERNEL_HEADERS_URL

  cd kernel-headers-${KERNEL_HEADERS_VERSION}

  apply-patches kernel-headers-${KERNEL_HEADERS_VERSION}

  make ARCH=$KERNEL_HEADERS_ARCH prefix=/ DESTDIR=$MUSL_DIR install
fi

#############################
# Build libpcap (if needed) #
#############################

if [ $FEATURE_DISCOVERY -eq 1 ]; then
  cd $BUILD_DIR

  fetch-dependency \
    libpcap-${LIBPCAP_VERSION} \
    libpcap-${LIBPCAP_VERSION}.tar.gz \
    $LIBPCAP_URL

  cd libpcap-${LIBPCAP_VERSION}

  apply-patches libpcap-${LIBPCAP_VERSION}

  export CC=musl-gcc

  if [ ! -f Makefile ]; then
    ./configure --prefix=$MUSL_DIR --target=$RUST_TARGET --host=$BUILD_HOST \
      --disable-shared \
      --disable-usb \
      --disable-bluetooth \
      --disable-dbus \
      --disable-yydebug \
      --with-pcap=linux
  fi

  make
  make install

  unset CC
fi

##########################
# Build the Arrow Client #
##########################

cd $SELF_DIR

export OPENSSL_STATIC=1
export OPENSSL_LIB_DIR=$MUSL_LIB
export OPENSSL_INCLUDE_DIR=$MUSL_INC

export LIBPCAP_STATIC=1

export CC_${RUST_TARGET//-/_}=musl-gcc

if [ ! -d .cargo ]; then
  mkdir .cargo
fi

if [ -f .cargo/config ]; then
  mv .cargo/config .cargo/config.old
fi

cat << EOF > .cargo/config
[target.${RUST_TARGET}]
ar = "${TOOLCHAIN_PREFIX}ar"
linker = "musl-gcc"
EOF

if [ $FEATURE_DISCOVERY -eq 1 ]; then
  cargo build -v --target $RUST_TARGET --features discovery --release
else
  cargo build -v --target $RUST_TARGET --release
fi

if [ -f .cargo/config.old ]; then
  mv .cargo/config.old .cargo/config
fi

${TOOLCHAIN_PREFIX}strip target/$RUST_TARGET/release/arrow-client
