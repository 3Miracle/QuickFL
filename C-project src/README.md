# libhcs4QHCS #

Libhcs is a C library implementing a number of partially homormophic encryption
schemes. Refer to https://github.com/tiehuis/libhcs.

QHCS is a high-performance asynchronous offloading framework based Intel QAT for partially homomorphic encryption algorithm.

Libhcs4QHCS is the QHCS version of libhcs.

Now, libhcs4QHCS have implemented Paillier’s offloading to QAT.

## Dependencies

    cd /yourworkspace
    git clone https://github.com/ColonelDan/libhcs4QHCS.git

QHCS is based QAT, first we need install QAT drive (hardware version we use is dh8970).

    cd /yourworkspace/libhcs4QHCS/tar
    tar -xzof QAT.tar.gz
    cd QAT
    chmod -R o-rwx *
    apt-get update
    apt-get install pciutils-dev
    apt-get install g++
    apt-get install pkg-config
    apt-get install libssl-dev
    ./configure
    make
    make install
    make samples-install
    service qat_service start

    export ICP_ROOT=/yourworkspace/libhcs4QHCS/tar/QAT

then, rewrite 2 item in all 3 QAT config file: /etc/c6xx_dev0.conf、/etc/c6xx_dev1.conf、/etc/c6xx_dev2.conf:

    CyNumConcurrentAsymRequests = 2048
    NumberCyInstances = 1

QHCS need a customed OpenSSL:

    cd /yourworkspace/libhcs4QHCS/tar
    tar -xzof  openssl-master-g.tar.gz
    cd openssl-master-g
    then, you can refer to OpenSSL homepage for install it.

Dependencies for libhcs:

    sudo apt-get install libgmp-dev cmake

## Installation

Assuming all dependencies are on your system, the following will work on a
typical linux system.

First, you need rewrite 2 macro base your dir path in CMakeLists.txt

    set(ICP_ROOT "/root/QAT")   #different for your machine
    set(SSL_ROOT "/home/dan/openssl-master-g")  #different for your machine

Then, you can install:

    cd /yourworkspace/libhcs4QHCS
    mkdir build
    cd build
    cmake ..
    make hcs
    sudo make install # Will install to /usr/local by default
    make QHCS_bench

To uninstall all installed files, one can run the following command:

    sudo xargs rm < install_manifest.txt

## benchmark

libhcs4QHCS gives a benchmark to test QHCS's performance.

After “make QHCS_bench”，then

    cd bin
    ./QHCS_bench
