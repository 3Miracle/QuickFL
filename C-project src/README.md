# libhcs-async #

C-project src is an efficient QAT asynchronous offloading implementation of the paillier homomorphic encryption/decryption algorithm based on **QAT** and **libhcs**. **libhcs** is a paillier implementation based on **GMP** (GNU Multiple Precision Arithmetic Library). **QAT** is a proposed by Intel as a QAT is a high-performance ASIC chip-based solution designed to accelerate data center security (OpenSSL symmetric/asymmetric encryption/decryption) and compression (DEFLATE compression) loads. Compared to general-purpose hardware accelerator such as FPGAs and GPUs, QAT accelerators offer performance and power efficiency advantages due to their highly customized ASIC chip design.

libhcs-async is a high-performance asynchronous offloading framework based Intel QAT for Paillier algorithm.We mainly transplants the modular exponentiation operator in the QAT driver for concurrent, concurrent and asynchronous designs.

## Dependencies

    cd /yourworkspace
    git clone https://github.com/3Miracle/QuickFL.git

libhcs-async is based QAT, first we need install QAT drive (hardware version we use is Intel® QuickAssist Adapter 8960).The download is located at https://www.intel.com/content/www/us/en/products/sku/125199/intel-quickassist-adapter-8960/downloads.html

    cd /yourworkspace/QAT_DIR
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


then, rewrite 2 item in all 3 QAT config file: /etc/c6xx_dev0.conf、/etc/c6xx_dev1.conf、/etc/c6xx_dev2.conf:

    CyNumConcurrentAsymRequests = 2048
    NumberCyInstances = 1

libhcs-async requires OpenSSL for coruntine calls:


    you can refer to OpenSSL homepage for install it.

Dependencies for libhcs:

    sudo apt-get install libgmp-dev cmake

## Installation

Assuming all dependencies are on your system, the following will work on a
typical linux system.

First, you need rewrite 2 macro base your dir path in CMakeLists.txt

    set(ICP_ROOT "/root/QAT_DIR")   #different for your machine
    set(SSL_ROOT "/home/OPENSSL_DIR")  #different for your machine

Then, you can install:

    cd /yourworkspace/
    mkdir build
    cd build
    cmake ..
    make hcs
    sudo make install # Will install to /usr/local by default

To uninstall all installed files, one can run the following command:

    sudo xargs rm < install_manifest.txt

## benchmark

