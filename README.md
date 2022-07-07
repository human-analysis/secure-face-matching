# [Secure Face Matching Using Fully Homomorphic Encryption](https://arxiv.org/abs/1805.00577)

By Vishnu Naresh Boddeti

# Introduction
Face Matching over encrypted feature vectors. The library contains three main parts, the SEAL library, the enrollment script and the authentication script.

The SEAL library is the cryptographic library from Microsoft Research, supporting the underlying fully homomorphic encryption functionality.

The library supports both 1:1 matching and 1:N matching. It also supports both the BFV (with integer quantization) scheme as well as the CKKS (real values) scheme.

The "face-matching/enrollment/enrollment-bfv-1-to-1.cpp" script implements the enrollment stage, for 1:1 matching using BFV scheme, where keys are generated, feature vector is obtained, feature vector is encrypted using the public key and encrypted feature vector is stored in database along with the public, relinearization and Galois keys (typically on the remote server). Note that the keys only need to be generated once per user.

The "face-matching/authentication/authentication-bfv-1-to-1.cpp" script implements the matching stage, for 1:1 matching using BFV scheme, a probe feature vector is obtained, probe is encrypted using the public key, encrypted feature vector is matched against encrypted gallery vector using the relinearization keys and Galois keys, the encrypted score is then decrypted using the private key (typically on the client).

# Assumptions
The face feature vectors are assumed be normalized to unit-norm both during enrollment as well as during the authentication stage. We then compute the inner product between the normalized features. This is equivalent to computing the cosine similarity between the un-normalized feature vectors.

# Citation

If you think this library is useful to your research, please cite:

    @article{boddeti2018secure,
        title={Secure Face Matching Using Fully Homomorphic Encryption},
        author={Boddeti, Vishnu Naresh},
        booktitle={IEEE International Conference on Biometrics: Theory, Applications, and Systems (BTAS)},
        year={2018}
    }
    
    @article{engelsma2020hers,
        title={HERS: Homomorphically Encrypted Representation Search},
        author={Joshua Engelsma, Anil Jain and Vishnu Boddeti},
        journal={arXiv:2003.12197},
        year={2020}
    }

# Installation

Installation involves compiling the SEAL library, the enrollment and authentication scripts. We have included a python script "data/gendata.py" that can generate fake data (64-dimensional vector) for the gallery and probe.

~~~~
$ git clone --recursive https://github.com/human-analysis/secure-face-matching.git
$ cd secure-face-matching
$ cd 3rdparty/SEAL/native/src/
$ cmake .
$ make clean; make; sudo make install
$ cd ../../../../face-matching/
$ cd enrollment
$ mkdir build; cd build
$ cmake ../
$ make clean; make
$ cd ../../authentication
$ mkdir build; cd build
$ cmake ../
$ make clean; make
$ cd ../../../data
$ python gendata.py
$ cd ../bin
~~~~

# Usage

Both enrollment and authentication take desired security level in bits as inputs. Options for security level supported are 128, 192 and 256 bits. Authentication takes an additional parameter, the number of gallery samples to match with. This should match the number of gallery samples enrolled.

## 1:1 Matching with BFV scheme

~~~~
$ ./enrollment-bfv-1-to-1 128
$ ./authentication-bfv-1-to-1 16 128
~~~~

## 1:N Matching with BFV scheme

~~~~
$ ./enrollment-bfv-1-to-n 128
$ ./authentication-bfv-1-to-n 16 128
~~~~

## 1:1 Matching with CKKS scheme

~~~~
$ ./enrollment-ckks-1-to-1 128
$ ./authentication-ckks-1-to-1 16 128
~~~~

## 1:N Matching with CKKS scheme

~~~~
$ ./enrollment-ckks-1-to-n 128
$ ./authentication-ckks-1-to-n 16 128
~~~~
