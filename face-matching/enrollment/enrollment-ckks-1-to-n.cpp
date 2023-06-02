///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : enrollment-ckks-1-to-n.cpp
//   Description : user face enrollment, key generation, feature encryption,
//                 feature storage in database, key storage
//                 uses CKKS scheme for 1:N matching
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 06/01/2023
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
#include <filesystem>
#include <cmath>

#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

int main(int argc, char **argv)
{

    cout << argv[1] << endl;
    int security_level = atoi(argv[1]);

    float precision;
    stringstream stream;

    auto scale = pow(2.0, 32);
    size_t poly_modulus_degree;
    EncryptionParameters parms(scheme_type::ckks);

    if (security_level == 128)
    {
        poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 20, 20, 30 }));
    }
    else if (security_level == 192)
    {
        poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 20, 20, 30 }));
    }
    else if (security_level == 256)
    {
        poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 20, 20, 30 }));
    }

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB" << endl;

    SEALContext context(parms);
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    PublicKey public_key;
    RelinKeys relin_key;
    GaloisKeys gal_key;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_key);
    keygen.create_galois_keys(gal_key);

    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);

    string name;
    ofstream ofile;

    // create directory to save keys
    auto created_new_directory
      = std::filesystem::create_directory("../data/keys/");
    if (not created_new_directory) {
        // Either creation failed or the directory was already present.
    }

    // save the keys (public, secret, relin and galios)
    name = "../data/keys/public_key_ckks_1_to_n.bin";
    cout << "Saving Public Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    public_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/secret_key_ckks_1_to_n.bin";
    cout << "Saving Secret Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    secret_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/relin_key_ckks_1_to_n.bin";
    cout << "Saving Relin Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    relin_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/galios_key_ckks_1_to_n.bin";
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
    ifile.open ("../data/gallery-1-to-n.bin", ios::in|ios::binary);

    ifile.read((char *)&dim_gallery, sizeof(int));
    ifile.read((char *)&num_gallery, sizeof(int));

    float gallery[num_gallery];
    Plaintext plain_matrix;
    vector<double> pod_vector;
    for (int i=0; i < dim_gallery; i++)
    {
        // Load gallery from file
        ifile.read((char *)&gallery, num_gallery * sizeof(float));

        // push dim i of all gallery into a vector of size poly_modulus_degree
        // assuming that gallery size is smaller than poly_modulus_degree
        // else need to chunk the gallery into blocks
        for (int j=0;j<slot_count;j++)
        {
            if ((0 <= j) and (j < num_gallery))
            {
                pod_vector.push_back((double) gallery[j]);
            }
            else{
                pod_vector.push_back((double) 0.0);
            }
        }

        // create directory to save encrypted gallery
        auto created_new_directory = std::filesystem::create_directory("../data/gallery/");
        if (not created_new_directory)
        {
            // Either creation failed or the directory was already present.
        }

        // Encrypt entire dim of gallery
        Ciphertext encrypted_matrix;
        ckks_encoder.encode(pod_vector, scale, plain_matrix);
        cout << "Encrypting Gallery Dim: " << i << endl;
        encryptor.encrypt(plain_matrix, encrypted_matrix);

        // Save encrypted feature vector to disk.
        name = "../data/gallery/encrypted_gallery_ckks_1_to_n_" + std::to_string(i) + ".bin";
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
