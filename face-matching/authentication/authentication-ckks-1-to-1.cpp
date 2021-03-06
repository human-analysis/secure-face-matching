///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : authentication.cpp
//   Description : user face authentication, probe feature encryption,
//                 probe feature matching with encrypted database, decrypt matching score
//                 uses CKKS scheme for 1:1 matching
//   Input       : needs gallery size as input
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 02/26/2020
////////////////////////////////////////////////////////////////////////////

#include <fstream>
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

int main(int argc, char **argv)
{
    cout << argv[1] << endl;
    int num_gallery = atoi(argv[1]);

    float precision;
    vector<double> pod_result;

    GaloisKeys gal_key;
    RelinKeys relin_key;
    PublicKey public_key;
    SecretKey secret_key;

    auto scale = pow(2.0, 20);
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

    ifstream ifile;
    string name;
    stringstream stream;

    // load back the keys (public, secret, evaluator and galois)
    name = "../data/keys/public_key_ckks_1_to_1.bin";
    cout << "Loading Public Key: " << name << endl;
    ifile.open(name.c_str(), ios::in|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        public_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = "../data/keys/secret_key_ckks_1_to_1.bin";
    cout << "Loading Private Key: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        secret_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = "../data/keys/galios_key_ckks_1_to_1.bin";
    cout << "Loading Galios Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        gal_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = "../data/keys/relin_key_ckks_1_to_1.bin";
    cout << "Loading Relin Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        relin_key.unsafe_load(context, stream);
    }
    ifile.close();
    stream.str(std::string());

    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    int slot_count = ckks_encoder.slot_count();

    // Load the Gallery
    vector<Ciphertext> encrypted_gallery;
    for (int i=0; i < num_gallery; i++)
    {
        name = "../data/gallery/encrypted_gallery_ckks_1_to_1_" + std::to_string(i) + ".bin";
        ifile.open(name.c_str(), ios::in|ios::binary);
        Ciphertext encrypted_matrix;
        stream << ifile.rdbuf();
        encrypted_matrix.load(context, stream);
        ifile.close();
        encrypted_gallery.push_back(encrypted_matrix);
    }

    int num_probe, dim_probe;
    ifile.open ("../data/probe-1-to-1.bin", ios::in|ios::binary);
    ifile.read((char *)&num_probe, sizeof(int));
    ifile.read((char *)&dim_probe, sizeof(int));

    float probe[dim_probe];
    Plaintext plain_probe;
    vector<double> pod_vector;

    for (int i=0; i < num_probe; i++)
    {
        // Load vector of probe from file
        ifile.read((char *)&probe, dim_probe * sizeof(float));

        // push probe into a vector of size poly_modulus_degree
        for (int j=0; j<slot_count; j++)
        {
            if ((0 <= j) and (j < dim_probe))
            {
                    pod_vector.push_back((double) probe[j]);
            }
            else{
                pod_vector.push_back((double) 0.0);
            }
        }

        // Encrypt entire vector of probe
        ckks_encoder.encode(pod_vector, scale, plain_probe);
        cout << "Encrypting Probe: " << i << endl;
        Ciphertext encrypted_probe;
        encryptor.encrypt(plain_probe, encrypted_probe);

        pod_vector.clear();
        vector<double> pod_result;

        for (int j=0; j < num_gallery; j++)
        {
            Ciphertext temp = Ciphertext(encrypted_probe);
            evaluator.multiply_inplace(temp, encrypted_gallery[j]);
            evaluator.relinearize_inplace(temp, relin_key);
            Ciphertext encrypted_result = Ciphertext(temp);
            for (int k=0; k<log2(slot_count); k++)
            {
                evaluator.rotate_vector(encrypted_result, pow(2,k), gal_key, temp);
                evaluator.add_inplace(encrypted_result, temp);
            }

            Plaintext plain_result;
            decryptor.decrypt(encrypted_result, plain_result);
            ckks_encoder.decode(plain_result, pod_result);

            float score = double(pod_result[0]);
            cout << "Matching Score (probe " << i << ", and gallery " << j << "): " << score << endl;
            pod_vector.clear();
        }
        cout << " " << endl;
    }
    cout << "Done" << endl;
    ifile.close();
    return 0;
}
