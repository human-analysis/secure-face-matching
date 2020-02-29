///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : enrollment-ckks-1-to-1.cpp
//   Description : user face enrollment, key generation, feature encryption,
//                 feature storage in database, key storage
//                 uses CKKS scheme for 1:1 matching
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 03/01/2020
////////////////////////////////////////////////////////////////////////////

#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <random>
#include <limits>

#include <time.h>
#include <cmath>

#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

int main()
{

    float precision;
    stringstream stream;

    auto scale = pow(2.0, 32);
    size_t poly_modulus_degree = 4096;

    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 20, 20, 30 }));

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB" << endl;

    auto context = SEALContext::Create(parms);
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    KeyGenerator keygen(context);
    GaloisKeys gal_key = keygen.galois_keys();
    RelinKeys relin_key = keygen.relin_keys();
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);

    string name;
    ofstream ofile;

    // save the keys (public, secret, relin and galios)
    name = "../data/keys/public_key_ckks_1_to_1.bin";
    cout << "Saving Public Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    public_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/secret_key_ckks_1_to_1.bin";
    cout << "Saving Secret Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    secret_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/relin_key_ckks_1_to_1.bin";
    cout << "Saving Relin Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    relin_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/galios_key_ckks_1_to_1.bin";
    cout << "Saving Galios Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    gal_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    int slot_count = ckks_encoder.slot_count();
    cout << "Plaintext matrix slot count: " << slot_count << endl;

    ifstream ifile;
    int num_gallery, dim_gallery;
    ifile.open ("../data/gallery-1-to-1.bin", ios::in|ios::binary);

    ifile.read((char *)&num_gallery, sizeof(int));
    ifile.read((char *)&dim_gallery, sizeof(int));

    Plaintext plain_matrix;
    float gallery[dim_gallery];
    vector<double> pod_vector;
    for (int i=0; i < num_gallery; i++)
    {
        // Load gallery from file
        ifile.read((char *)&gallery, dim_gallery * sizeof(float));

        // push gallery into a vector of size poly_modulus_degree
        // actually we should be able to squeeze two gallery instances into one vector
        // this depends on implementation, can get 2x speed up and 2x less storage
        for (int j=0;j<slot_count;j++)
        {
            if ((0 <= j) and (j < dim_gallery))
            {
                pod_vector.push_back((double) gallery[j]);
            }
            else{
                pod_vector.push_back((double) 0.0);
            }
        }

        // Encrypt entire vector of gallery
        Ciphertext encrypted_matrix;
        ckks_encoder.encode(pod_vector, scale, plain_matrix);
        cout << "Encrypting Gallery: " << i << endl;
        encryptor.encrypt(plain_matrix, encrypted_matrix);

        // Save encrypted feature vector to disk.
        name = "../data/gallery/encrypted_gallery_ckks_1_to_1_" + std::to_string(i) + ".bin";
        ofile.open(name.c_str(), ios::out|ios::binary);
        encrypted_matrix.save(stream);
        ofile << stream.str();
        ofile.close();
        pod_vector.clear();
        stream.str(std::string());
    }
    cout << "Done" << endl;
    ifile.close();
    return 0;
}