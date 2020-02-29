///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : enrollment-bfv-1-to-n.cpp
//   Description : user face enrollment, key generation, feature encryption,
//                 feature storage in database, key storage
//                 uses BFV scheme for 1:N matching
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
    size_t poly_modulus_degree;

    precision = 125; // precision of 1/125 = 0.004
    poly_modulus_degree = 4096;

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); // seems like 16 also works

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
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);

    string name;
    ofstream ofile;

    // save the keys (public, secret, relin and galios)
    name = "../data/keys/public_key_bfv_1_to_n.bin";
    cout << "Saving Public Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    public_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/secret_key_bfv_1_to_n.bin";
    cout << "Saving Secret Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    secret_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/relin_key_bfv_1_to_n.bin";
    cout << "Saving Relin Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    relin_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/galios_key_bfv_1_to_n.bin";
    cout << "Saving Galios Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    gal_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());
    int slot_count = batch_encoder.slot_count();
    cout << "Plaintext matrix slot count: " << slot_count << endl;

	ifstream ifile;
    int num_gallery, dim_gallery;
    ifile.open ("../data/gallery-1-to-n.bin", ios::in|ios::binary);

    ifile.read((char *)&dim_gallery, sizeof(int));
    ifile.read((char *)&num_gallery, sizeof(int));

    Plaintext plain_matrix;
    float gallery[num_gallery];
    vector<int64_t> pod_matrix;
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
                int a = (int64_t) roundf(precision*gallery[j]);
                pod_matrix.push_back(a);
            }
            else{
                pod_matrix.push_back((int64_t) 0);
            }
        }

        // Encrypt entire dim of gallery
        Ciphertext encrypted_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);
        cout << "Encrypting Gallery Dim: " << i << endl;
        encryptor.encrypt(plain_matrix, encrypted_matrix);

        // Save encrypted feature vector to disk.
        name = "../data/gallery/encrypted_gallery_bfv_1_to_n_" + std::to_string(i) + ".bin";
        ofile.open(name.c_str(), ios::out|ios::binary);
        encrypted_matrix.save(stream);
        ofile << stream.str();
        ofile.close();
        pod_matrix.clear();
        stream.str(std::string());
    }
    cout << "Done" << endl;
    ifile.close();
    return 0;
}
