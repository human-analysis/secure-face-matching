///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching (Eyeverify/Zoloz)
//   File        : enrollment.cpp
//   Description : user face enrollment, key generation, feature encryption,
//                 feature storage in database, key storage
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
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

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context)
{
    cout << "/ Encryption parameters:" << endl;
    cout << "| poly_modulus: " << context.poly_modulus().to_string() << endl;

    /*
    Print the size of the true (product) coefficient modulus
    */
    cout << "| coeff_modulus size: " 
        << context.total_coeff_modulus().significant_bit_count() << " bits" << endl;

    cout << "| plain_modulus: " << context.plain_modulus().value() << endl;
    cout << "\\ noise_standard_deviation: " << context.noise_standard_deviation() << endl;
    cout << endl;
}

int main()
{

    int nrows, slot_count, row_size;
    EncryptionParameters parms;
    
    float precision = 125; // precision of 1/125 = 0.004
    parms.set_poly_modulus("1x^4096 + 1"); // 4096/2 is maximum feature vector size
    parms.set_coeff_modulus(coeff_modulus_128(4096)); // change to coeff_modulus_192 for 192 bits of security
    parms.set_plain_modulus(40961);

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB" << endl;

    SEALContext context(parms);
    print_parameters(context);
    auto qualifiers = context.qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.enable_batching << endl;
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    GaloisKeys gal_keys;
    EvaluationKeys ev_keys;
    keygen.generate_galois_keys(30, gal_keys);
    keygen.generate_evaluation_keys(30, ev_keys);

    Evaluator evaluator(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    PolyCRTBuilder crtbuilder(context);

    ofstream ofile;
    string name;
    
    // save the keys (public, secret, evaluator and galois)
    name = "../data/public_key.bin";
    cout << "Saving Public Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    public_key.save(ofile);
    ofile.close();

    name = "../data/secret_key.bin";
    cout << "Saving Secret Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    secret_key.save(ofile);
    ofile.close();

    name = "../data/evaluator_key.bin";
    cout << "Saving Evaluation Keys: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    ev_keys.save(ofile);
    ofile.close();

    name = "../data/galois_key.bin";
    cout << "Saving Galois Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    gal_keys.save(ofile);
    ofile.close();

    nrows = 2;
    slot_count = crtbuilder.slot_count();
    row_size = slot_count / nrows;

    cout << "Plaintext matrix row size: " << row_size << endl;

    int num, dim;
    ifstream ifile;
    ifile.open ("../data/gallery.bin", ios::in|ios::binary);

    ifile.read((char *)&num, sizeof(int));
    ifile.read((char *)&dim, sizeof(int));

    int count = 0;
    float data[dim * num];
    Plaintext plain_matrix1;
    vector<int64_t> pod_matrix1;
    for (int i=0; i < num; i++)
    {
        // Load vector of data from file
        ifile.read((char *)&data[i*dim], dim * sizeof(float));

        // push data into a vector of size 4096
        // actually we should be able to squeeze two data instances into one vector
        // this depends on implementation, can get 2x speed up and 2x less storage
        for (int j=0;j<row_size*nrows;j++)
        {
            if ((0 <= j) and (j < dim))
            {
                int a = (int64_t) roundf(precision*data[count]);
                pod_matrix1.push_back(a);
                count++;
            }
            else{
                pod_matrix1.push_back((int64_t) 0);
            }
        }

        // Encrypt entire vector of data
        crtbuilder.compose(pod_matrix1, plain_matrix1);
        Ciphertext encrypted_matrix1;
        cout << "Encrypting Gallery: " << i << endl;
        encryptor.encrypt(plain_matrix1, encrypted_matrix1);

        // Save encrypted feature vector to disk.
        name = "../data/encrypted_gallery_" + std::to_string(i) + ".bin";
        ofile.open(name.c_str(), ios::out|ios::binary);
        encrypted_matrix1.save(ofile);
        ofile.close();
        pod_matrix1.clear();
    }
    cout << "Done" << endl;
    ifile.close();
    return 0;
}