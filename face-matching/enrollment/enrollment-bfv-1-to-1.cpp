///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : enrollment-bfv-1-to-1.cpp
//   Description : user face enrollment, key generation, feature encryption,
//                 feature storage in database, key storage
//                 uses BFV scheme for 1:1 matching
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 07/06/2022
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

#include <time.h>
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
    size_t poly_modulus_degree;

    precision = 125; // precision of 1/125 = 0.004
    EncryptionParameters parms(scheme_type::BFV);

    if (security_level == 128)
    {
        poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc128));
    }
    else if (security_level == 192)
    {
        poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc192));
    }
    else if (security_level == 256)
    {
        poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc256));
    }    
   
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

    // create directory to save keys
    auto created_new_directory
      = std::filesystem::create_directory("../data/keys/");
    if (not created_new_directory) {
        // Either creation failed or the directory was already present.
    }

    // save the keys (public, secret, relin and galios)
    name = "../data/keys/public_key_bfv_1_to_1.bin";
    cout << "Saving Public Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    public_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/secret_key_bfv_1_to_1.bin";
    cout << "Saving Secret Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    secret_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/relin_key_bfv_1_to_1.bin";
    cout << "Saving Relin Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    relin_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());

    name = "../data/keys/galios_key_bfv_1_to_1.bin";
    cout << "Saving Galios Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    gal_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());
    int slot_count = batch_encoder.slot_count();

    ifstream ifile;
    int num_gallery, dim_gallery;
    ifile.open ("../data/gallery-1-to-1.bin", ios::in|ios::binary);

    ifile.read((char *)&num_gallery, sizeof(int));
    ifile.read((char *)&dim_gallery, sizeof(int));

    Plaintext plain_matrix;
    float gallery[dim_gallery];
    vector<int64_t> pod_matrix;
    for (int i=0; i < num_gallery; i++)
    {
        // Load gallery from file
        ifile.read((char *)gallery, dim_gallery * sizeof(float));

        // push gallery into a vector of size poly_modulus_degree
        // actually we should be able to squeeze two gallery instances into one vector
        // this depends on implementation, can get 2x speed up and 2x less storage
        for (int j=0;j<slot_count / 2;j++)
        {
            if ((0 <= j) and (j < dim_gallery))
            {
                int a = (int64_t) roundf(precision*gallery[j]);
                pod_matrix.push_back(a);
            }
            else{
                pod_matrix.push_back((int64_t) 0);
            }
        }

        // create directory to save encrypted gallery
        auto created_new_directory = std::filesystem::create_directory("../data/gallery/");
        if (not created_new_directory)
        {
            // Either creation failed or the directory was already present.
        }

        // Encrypt entire vector of gallery
        Ciphertext encrypted_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);
        cout << "Encrypting Gallery: " << i << endl;
        encryptor.encrypt(plain_matrix, encrypted_matrix);

        // Save encrypted feature vector to disk.
        name = "../data/gallery/encrypted_gallery_bfv_1_to_1_" + std::to_string(i) + ".bin";
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
