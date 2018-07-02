# Introduction
Face Matching over encrypted feature vectors. The library contains three main parts, the SEAL library, the enrollment script and the authentication script.

The SEAL library is the cryptographic library from Microsoft Research, supporting the underlying fully homomorphic encryption functionality.

The "face-matching/enrollment/enrollment.cpp" script implements the enrollment stage where keys are generated, feature vector is obtained, feature vector is encrypted using the public key and encrypted feature vector is stored in database along with the public, evaluation and Galois keys (typically on the remote server). Note that the keys only need to be generated once per user.

The "face-matching/authentication/authentication.cpp" script implements the matching stage,  a probe feature vector is obtained, probe is encrypted using the public key, encrypted feature vector is matched against encrypted gallery vector using the evaluation keys and Galois keys, the encrypted score is then decrypted using the private key (typically on the client).

# Assumptions
The face feature vectors are assumed be normalized to unit-norm both during enrollment as well as during the authentication stage. We then compute the inner product between the normalized features. This is equivalent to computing the cosing similarity between the un-normalized feature vectors.

# Installation and Usage

Installation involves compiling the SEAL library, the enrollment and authentication scripts. We have included a python script "data/gendata.py" that can generate fake data (512-dimensional vector) for the gallery and probe. The code has been tested for matching 1 probe to 1 gallery.

$ cd "this directory"
$ cd 3rdparty/SEAL-2.3/SEAL
$ make clean; make
$ cd ../../../face-matching/
$ cd enrollment
$ make clean; make
$ cd ../authentication
$ make clean; make
$ cd ../data
$ python gendata.py
$ cd ../bin
$ ./enrollment
$ ./authenticate