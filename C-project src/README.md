# libhcs-async #

C-project src is an efficient QAT asynchronous offloading implementation of the paillier homomorphic encryption/decryption algorithm based on **QAT** and **libhcs**. **libhcs** is a paillier implementation based on **GMP** (GNU Multiple Precision Arithmetic Library). **QAT** is a proposed by Intel as a QAT is a high-performance ASIC chip-based solution designed to accelerate data center security (OpenSSL symmetric/asymmetric encryption/decryption) and compression (DEFLATE compression) loads. Compared to general-purpose hardware accelerator such as FPGAs and GPUs, QAT accelerators offer performance and power efficiency advantages due to their highly customized ASIC chip design.

libhcs-async is a high-performance asynchronous offloading framework based Intel QAT for Paillier algorithm.We mainly transplants the modular exponentiation operator in the QAT driver for concurrent, concurrent and asynchronous designs.

## Dependencies

    cd /yourworkspace
    git clone https://github.com/3Miracle/QuickFL.git

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
