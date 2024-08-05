# QuickFL
This is the source repo for Infocom2025 paper "QuickFL: A QAT Aided Acceleration Framework for Communication and Computation Efficient Federated Learning"
# Structure
This includes the QAT hardware accelerated gradient homomorphic encryption and decryption C-project software stack(located in the "C-project src" folder), including the homomorphic encryption and decryption Python call interface in the compiled dynamic library **libhcs.so**, and includes an implementation of the federated learning Python call interface based on the Ctypes implementation(located in the Python API folder).   
***
Based on the compiled dynamic library **libhcs.so** combined with the **Python API** can be used directly out of the box, apply to other privacy computing frameworks that require homomorphic encryption and decryption.
