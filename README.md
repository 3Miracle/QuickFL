# QuickFL

Welcome to the source repository for the Infocom2025 paper "QuickFL: A QAT Aided Acceleration Framework for Communication and Computation Efficient Federated Learning".

## Table of Contents
- [Introduction](#introduction)
- [Structure](#structure)
- [Usage](#usage)

## Introduction

QuickFL is a federated learning training acceleration solution based on QAT hardware acceleration cards. It leverages QAT-accelerated DEFLATE encoding technology combined with an adaptive error feedback gradient compression algorithm to reduce communication overhead. The framework also features a high-performance homomorphic encryption and decryption software stack, designed around QAT-accelerated modular exponentiation operations, to minimize computational costs. This solution enables joint optimization of computation and communication overhead in homomorphic encryption-based federated learning, utilizing QAT hardware acceleration cards.

## Structure

The repository is organized into several key components:

- **C-project src**: Contains the software stack for QAT hardware-accelerated gradient homomorphic encryption and decryption. This includes the source code and necessary build files.
- **libhcs.so**: A compiled dynamic library providing homomorphic encryption and decryption functionalities. This library can be accessed via Python using the provided interface.
- **Python API**: Implements a Python call interface using Ctypes, allowing for easy integration with the **libhcs.so** library. This component enables the use of homomorphic encryption and decryption in other privacy computing frameworks.

## Usage

With the compiled dynamic library `libhcs.so` and the `Python API`, you can use the framework **right out of the box**. Additionally, you can perform further development on the C-project source code and recompile the dynamic library if needed.
